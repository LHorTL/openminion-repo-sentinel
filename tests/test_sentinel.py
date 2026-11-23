"""Comprehensive E2E tests exercising OpenMinion 0.1.24 SDK building blocks & bug reproducers."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path

from openminion import (
    APIRuntime,
    Agent,
    AgentOutputValidationError,
    Handoff,
    OpenMinionConfig,
)
from openminion.modules.llm.providers.behavior import resolve_behavior_profile
from openminion.modules.llm.providers.cortensor.adapter import CortensorProvider
from openminion.modules.llm.schemas import LLMRequest, Message
from openminion.modules.memory.portability import load_bundle
from openminion.modules.tool.errors import ToolRuntimeError

from sentinel.agent import build_runtime_config, run_repo_triage
from sentinel.memory_store import DEFAULT_BUNDLE_FILENAME
from sentinel.models import ReleaseBrief, ReleaseTriageReport
from sentinel.tools import (
    audit_dependency_and_secret_context,
    check_release_readiness,
    inspect_git_repo,
    scan_secret_leaks,
    scoped_write_root,
    write_triage_report,
)


class TestRepoTriageSentinel(unittest.TestCase):
    def test_read_only_tools_trigger_zero_approval_prompts(self) -> None:
        """Verify min_scope='READ_ONLY' custom @tools execute with 0 approval prompts under mode='ask'."""
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "ro_pkg"
            repo.mkdir()
            (repo / "README.md").write_text("# RO Package\n", encoding="utf-8")
            (repo / "LICENSE").write_text("MIT\n", encoding="utf-8")
            (repo / ".gitignore").write_text(".venv/\n", encoding="utf-8")
            (repo / "test_ok.py").write_text("def test_ok(): assert True\n", encoding="utf-8")

            approvals: list[str] = []

            def record_approval(tool_name: str, args: dict, approval_id: str) -> bool:
                approvals.append(tool_name)
                return True

            result, diag = run_repo_triage(
                str(repo),
                approval_callback=record_approval,
                enable_handoff=False,
                run_brief_subagent=False,
                use_local_demo_llm=True,
            )

            self.assertEqual(
                approvals,
                [],
                "READ_ONLY custom tools must not trigger approval_callback under allow_read_only_without_prompt",
            )
            self.assertIsInstance(result.output, ReleaseTriageReport)
            self.assertTrue(result.output.release_ready)
            self.assertGreater(diag["stream_events_count"], 0)

    def test_clean_repo_full_openminion_turn_handoff_subagent_stream_and_write(self) -> None:
        """Full E2E: APIRuntime.from_config, run_stream, Handoff, subagent, approval gate, MemoryBundle."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = root / "clean_pkg"
            repo.mkdir()
            (repo / "README.md").write_text("# Clean Package\n", encoding="utf-8")
            (repo / "LICENSE").write_text("MIT\n", encoding="utf-8")
            (repo / ".gitignore").write_text(".venv/\n", encoding="utf-8")
            (repo / "test_basic.py").write_text("def test_ok(): assert True\n", encoding="utf-8")

            state_dir = root / "state"
            report_out = repo / "triage.md"
            approvals: list[str] = []
            streamed: list[dict] = []

            def approve_all(tool_name: str, args: dict, approval_id: str) -> bool:
                approvals.append(tool_name)
                return True

            result, diag = run_repo_triage(
                str(repo),
                report_out_path=str(report_out),
                approval_callback=approve_all,
                on_stream_event=streamed.append,
                state_dir=state_dir,
                use_local_demo_llm=True,
            )

            self.assertIsInstance(result.output, ReleaseTriageReport)
            self.assertEqual(result.output.repo_name, "clean_pkg")
            self.assertTrue(result.output.release_ready)
            self.assertEqual(result.output.risk_level, "LOW")
            self.assertEqual(result.output.secret_findings, [])
            self.assertEqual(result.output.checklist_gaps, [])
            self.assertEqual(result.output.security_specialist_verdict, "CLEAR")
            self.assertIsInstance(result.output.release_brief, ReleaseBrief)
            self.assertEqual(result.output.release_brief.repo_name, "clean_pkg")
            self.assertEqual(result.output.diff_from_previous.trend, "baseline")

            # Verify only Handoff (WRITE_SAFE) and write_triage_report (dangerous) prompted; READ_ONLY tools did not.
            self.assertIn("transfer_to_security_specialist", approvals)
            self.assertIn("write_triage_report", approvals)
            self.assertNotIn("inspect_git_repo", approvals)
            self.assertNotIn("scan_secret_leaks", approvals)
            self.assertNotIn("check_release_readiness", approvals)

            self.assertTrue(report_out.exists(), "write_triage_report should persist report when approved")
            self.assertIn("Release Triage Report: clean_pkg", report_out.read_text(encoding="utf-8"))
            self.assertGreaterEqual(diag["builtin_tool_count"], 50)
            self.assertIn("transfer_to_security_specialist", diag["handoff_tools"])
            self.assertTrue(diag["handoff_executed"])
            self.assertTrue(diag["subagent_executed"])
            self.assertTrue(str(diag["subagent_context_id"]).startswith("subagent-"))
            self.assertGreater(len(streamed), 5)
            self.assertEqual(diag["memory_bundle_saved_items"], 1)
            self.assertTrue((state_dir / DEFAULT_BUNDLE_FILENAME).is_file())

    def test_dirty_secret_and_specialist_risks_flag_critical_and_block_release(self) -> None:
        """Verify secret scanning + Handoff security_specialist detect leaks, .env, and Dockerfile :latest."""
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "leaky_pkg"
            repo.mkdir()
            # Synthetic fake token constructed dynamically so secret scanners never flag the test file itself.
            fake_token = "AKIA" + "1234567890ABCDEF"
            (repo / "config.py").write_text(f'EXAMPLE = "{fake_token}"\n', encoding="utf-8")
            (repo / ".env").write_text("DEBUG=1\n", encoding="utf-8")
            (repo / "Dockerfile").write_text("FROM python:latest\n", encoding="utf-8")

            result, diag = run_repo_triage(
                str(repo),
                approval_callback=lambda name, args, aid: True,
                run_brief_subagent=False,
                use_local_demo_llm=True,
            )

            self.assertFalse(result.output.release_ready)
            self.assertEqual(result.output.risk_level, "CRITICAL")
            self.assertEqual(len(result.output.secret_findings), 1)
            self.assertEqual(result.output.secret_findings[0].rule, "aws_access_key")
            # Ensure secret material itself is never echoed in context_hint or summary.
            serialized = result.output.model_dump_json()
            self.assertNotIn(fake_token, serialized)
            self.assertEqual(result.output.security_specialist_verdict, "BLOCK_RELEASE")
            self.assertGreaterEqual(len(result.output.dependency_risks), 1)
            self.assertGreaterEqual(len(result.output.checklist_gaps), 3)
            self.assertTrue(diag["handoff_executed"])

    def test_memory_bundle_cross_run_export_import_and_diff(self) -> None:
        """Run 1 saves MemoryBundle baseline; Run 2 imports bundle and detects resolved secrets & improved trend."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = root / "evolving_pkg"
            repo.mkdir()
            state_dir = root / "state"

            # Run 1: leaky & missing docs.
            fake_token = "AKIA" + "1234567890ABCDEF"
            (repo / "config.py").write_text(f'EXAMPLE = "{fake_token}"\n', encoding="utf-8")
            res1, diag1 = run_repo_triage(
                str(repo),
                approval_callback=lambda name, args, aid: True,
                state_dir=state_dir,
                run_brief_subagent=False,
                use_local_demo_llm=True,
            )
            self.assertEqual(res1.output.risk_level, "CRITICAL")
            self.assertEqual(res1.output.diff_from_previous.trend, "baseline")
            self.assertEqual(diag1["memory_bundle_prior_items"], 0)
            self.assertEqual(diag1["memory_bundle_saved_items"], 1)

            # Remediate secret + add release hygiene artifacts before Run 2.
            (repo / "config.py").write_text('EXAMPLE = os.environ.get("AWS_ACCESS_KEY_ID", "")\n', encoding="utf-8")
            (repo / "README.md").write_text("# Fixed\n", encoding="utf-8")
            (repo / "LICENSE").write_text("MIT\n", encoding="utf-8")
            (repo / ".gitignore").write_text(".venv/\n", encoding="utf-8")
            (repo / "test_fixed.py").write_text("def test_ok(): assert True\n", encoding="utf-8")

            res2, diag2 = run_repo_triage(
                str(repo),
                approval_callback=lambda name, args, aid: True,
                state_dir=state_dir,
                run_brief_subagent=False,
                use_local_demo_llm=True,
            )
            self.assertTrue(res2.output.release_ready)
            self.assertEqual(res2.output.risk_level, "LOW")
            self.assertEqual(diag2["memory_bundle_prior_items"], 1)
            self.assertEqual(diag2["memory_bundle_saved_items"], 2)
            diff = res2.output.diff_from_previous
            self.assertIsNotNone(diff)
            self.assertTrue(diff.has_previous_run)
            self.assertEqual(diff.trend, "improved")
            self.assertIn("config.py:1:aws_access_key", diff.resolved_secrets)
            self.assertEqual(diff.new_secrets, [])
            self.assertIn("Missing README.md", diff.resolved_gaps)

            # Verify persisted MemoryBundle file reloads cleanly via OpenMinion portability API.
            bundle = load_bundle(state_dir / DEFAULT_BUNDLE_FILENAME)
            self.assertEqual(len(bundle.items), 2)
            self.assertEqual(bundle.metadata["latest_repo"], "evolving_pkg")

    def test_approval_callback_blocks_dangerous_write_tool(self) -> None:
        """Denying write_triage_report prevents disk write & reproduces Finding #3 output_type collision."""
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "guarded_pkg"
            repo.mkdir()
            (repo / "README.md").write_text("# Guarded\n", encoding="utf-8")
            (repo / "LICENSE").write_text("MIT\n", encoding="utf-8")
            (repo / ".gitignore").write_text(".venv/\n", encoding="utf-8")
            (repo / "test_ok.py").write_text("def test_ok(): pass\n", encoding="utf-8")

            report_out = repo / "blocked" / "triage.md"
            seen_approvals: list[tuple[str, bool]] = []

            def deny_writes(tool_name: str, args: dict, approval_id: str) -> bool:
                allow = tool_name != "write_triage_report"
                seen_approvals.append((tool_name, allow))
                return allow

            # OpenMinion 0.1.24 returns plain-text "Confirmation denied. The action was not run."
            # on callback denial, triggering AgentOutputValidationError when output_type is a BaseModel
            # (documented as Finding #3 in SDK_FEEDBACK_REPORT.md + Patch 0005).
            with self.assertRaises(AgentOutputValidationError) as ctx:
                run_repo_triage(
                    str(repo),
                    report_out_path=str(report_out),
                    approval_callback=deny_writes,
                    run_brief_subagent=False,
                    use_local_demo_llm=True,
                )
            self.assertIn("not run", ctx.exception.raw_text.lower())
            self.assertFalse(report_out.exists(), "Denied dangerous tool must not write to disk")
            self.assertTrue(
                any(name == "write_triage_report" and not ok for name, ok in seen_approvals)
            )

    def test_write_triage_report_path_traversal_and_git_guard(self) -> None:
        """Verify strict workspace containment rejects .. escapes, .git/ writes, and LLM root-override args."""
        from pydantic import ValidationError

        # Security check: workspace_root must NOT be exposed in the LLM-facing @tool args schema.
        self.assertNotIn("workspace_root", write_triage_report.tool_args_model.model_fields)
        with self.assertRaises(ValidationError):
            write_triage_report.tool_args_model.model_validate(
                {"output_path": "escape.md", "markdown_body": "# Bad", "workspace_root": "/"}
            )

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = root / "ws"
            workspace.mkdir()
            outside = root / "escape.md"

            # Without scoped_write_root, fail closed against cwd (temp outside path is rejected).
            with self.assertRaises(ValueError):
                write_triage_report(str(outside), "# Bad")
            self.assertFalse(outside.exists())

            # Inside scoped_write_root, relative .., absolute outside path, and .git/ are all rejected.
            with scoped_write_root(workspace):
                with self.assertRaises(ValueError):
                    write_triage_report("../escape.md", "# Bad")
                with self.assertRaises(ValueError):
                    write_triage_report(str(outside), "# Bad")
                with self.assertRaises(ValueError):
                    write_triage_report(str(workspace / ".git" / "config"), "# Bad")
                self.assertFalse(outside.exists())
                # In-workspace write succeeds cleanly.
                ok_json = json.loads(
                    write_triage_report(str(workspace / "reports" / "ok.md"), "# Safe\n")
                )
                self.assertTrue(ok_json["written"])
                self.assertTrue((workspace / "reports" / "ok.md").is_file())

    def test_repro_cortensor_provider_fallback_tool_call_bug(self) -> None:
        """Repro Finding #1 (S-Tier): CortensorProvider drops /api/v2/completions fallback tool calls."""
        cp = CortensorProvider()
        req = LLMRequest(
            messages=[Message(role="user", content="inspect repo")],
            tools=[
                {
                    "name": "inspect_git_repo",
                    "description": "inspect repo",
                    "input_schema": {
                        "type": "object",
                        "properties": {"repo_path": {"type": "string"}},
                    },
                }
            ],
        )
        bp = resolve_behavior_profile(
            provider="cortensor",
            model="gpt-oss-20b",
            base_url="http://127.0.0.1:8080/api/v2/completions",
        )
        prompt = cp._build_completion_prompt(req)
        self.assertIn('"tool_calls"', prompt)

        resp_payload = {
            "id": "cmpl-cortensor-1",
            "model": "gpt-oss-20b",
            "choices": [
                {
                    "index": 0,
                    "text": json.dumps(
                        {
                            "tool_calls": [
                                {"name": "inspect_git_repo", "arguments": {"repo_path": "."}}
                            ]
                        }
                    ),
                    "finish_reason": "stop",
                }
            ],
        }
        parsed = cp._parse_response_payload(
            response_payload=resp_payload,
            request=req,
            tool_call_strategy="hybrid",
            fallback_model="gpt-oss-20b",
            behavior_profile=bp,
        )
        # Bug in openminion==0.1.24 (cortensor/adapter.py:470): fallback_enabled=False drops choice.text.
        self.assertEqual(parsed["tool_calls"], [])
        self.assertIn(
            "choice.text",
            parsed["tool_call_normalization"].get("tool_call_skipped_fallback_sources", []),
        )

    def test_repro_handoff_shared_tool_collision(self) -> None:
        """Repro Finding #2 (S-Tier): Nested agent sharing a @tool on the same APIRuntime crashes."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            cfg, _ = build_runtime_config(state_dir=p, provider="openai", api_key="k")
            cfg.agents["openminion"].provider = "echo"
            rt = APIRuntime.from_config(config=cfg, home_root=p, data_root=p)
            try:
                peer = Agent(
                    name="dup_peer",
                    instructions="check",
                    runtime=rt,
                    tools=[scan_secret_leaks],
                )
                parent = Agent(
                    name="dup_parent",
                    instructions="audit",
                    runtime=rt,
                    tools=[scan_secret_leaks],
                    handoffs=[Handoff(target=peer)],
                )
                with rt.tools.temporary_registration_scope(), ExitStack() as risk_scope:
                    reg_tools, reg_profiles = parent._register_tools_for_run(rt.tools, risk_scope)
                    try:
                        with self.assertRaises(ToolRuntimeError) as ctx:
                            peer.run("scan")
                        self.assertIn("already registered", str(ctx.exception).lower())
                    finally:
                        parent._unregister_tools(rt.tools, reg_tools, reg_profiles)
            finally:
                rt.close()

    def test_repro_programmatic_from_config_missing_default_channel_bug(self) -> None:
        """Repro Finding #4 (A-Tier): APIRuntime.from_config crashes on turn 1 when default_channel is omitted."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            bad_cfg = OpenMinionConfig.from_dict(
                {"agents": {"openminion": {"provider": "echo"}}}
            )
            rt = APIRuntime.from_config(config=bad_cfg, home_root=p, data_root=p)
            try:
                ag = Agent(name="broken_channel", instructions="hi", runtime=rt)
                with self.assertRaises(RuntimeError) as ctx:
                    ag.run("hello")
                self.assertIn("invalid_channel", str(ctx.exception))
            finally:
                rt.close()

            # Explicitly passing default_channel="console" (as build_runtime_config does) succeeds.
            good_cfg = OpenMinionConfig.from_dict(
                {"agents": {"openminion": {"provider": "echo", "default_channel": "console"}}}
            )
            rt2 = APIRuntime.from_config(config=good_cfg, home_root=p / "ok", data_root=p / "ok")
            try:
                res = Agent(name="ok_channel", instructions="hi", runtime=rt2).run("hello")
                self.assertIn("hello", res.text.lower())
            finally:
                rt2.close()

    def test_direct_tools_binary_skip_and_prose_wrapped_json_recovery(self) -> None:
        """Verify direct tool outputs, binary null-byte skipping, specialist audit, and JSON recovery."""
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "unit_repo"
            repo.mkdir()
            (repo / "README.md").write_text("# Demo\n", encoding="utf-8")
            (repo / "blob.bin").write_bytes(b"\x00\x01" + b"AKIA" + b"1234567890ABCDEF\x00")
            (repo / "requirements.txt").write_text("requests\npydantic>=2.0\n", encoding="utf-8")

            git_meta = json.loads(inspect_git_repo(str(repo)))
            self.assertEqual(git_meta["repo_name"], "unit_repo")
            sec = json.loads(scan_secret_leaks(str(repo)))
            self.assertTrue(sec["clean"], "Binary files containing null bytes must be skipped")
            qa = json.loads(check_release_readiness(str(repo)))
            self.assertTrue(qa["has_readme"])
            self.assertFalse(qa["has_license"])
            spec = json.loads(audit_dependency_and_secret_context(str(repo)))
            self.assertEqual(spec["verdict"], "REVIEW_REQUIRED")
            self.assertEqual(len(spec["dependency_risks"]), 1)

        # Exercise OpenMinion Agent._coerce_output JSON recovery & strict failure handling.
        agent = Agent[str, ReleaseTriageReport](output_type=ReleaseTriageReport)
        wrapped = (
            "Here is the structured verdict:\n"
            + json.dumps(
                {
                    "repo_name": "unit_repo",
                    "release_ready": True,
                    "risk_level": "LOW",
                    "secret_findings": [],
                    "checklist_gaps": [],
                    "recommended_actions": [],
                    "summary": "All clear.",
                }
            )
            + "\nDone."
        )
        coerced = agent._coerce_output(wrapped)
        self.assertEqual(coerced.repo_name, "unit_repo")

        with self.assertRaises(AgentOutputValidationError):
            agent._coerce_output("Not JSON at all")

    def test_openminion_doctor_cli_json_and_windows_checks(self) -> None:
        """Verify openminion doctor --json diagnostics including Finding #5 Windows warnings."""
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "config.json"
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "openminion",
                    "--home-root",
                    td,
                    "--data-root",
                    td,
                    "--config",
                    str(cfg),
                    "config",
                    "init",
                ],
                check=True,
                capture_output=True,
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "openminion",
                    "--home-root",
                    td,
                    "--data-root",
                    td,
                    "--config",
                    str(cfg),
                    "doctor",
                    "--json",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0)
            payload = json.loads(proc.stdout)
            checks_by_id = {c["id"]: c for c in payload["checks"]}
            self.assertIn("identity.bundle", checks_by_id)
            self.assertEqual(checks_by_id["identity.bundle"]["status"], "warn")
            if os.name == "nt":
                # Finding #5: Windows synthesizes 0o666/0o777 st_mode, triggering 3 bogus warnings.
                self.assertEqual(
                    checks_by_id["security.filesystem.config_permissions"]["status"],
                    "warn",
                )
                self.assertIn(
                    "world-writable",
                    checks_by_id["security.filesystem.config_permissions"]["message"].lower(),
                )


if __name__ == "__main__":
    unittest.main()
