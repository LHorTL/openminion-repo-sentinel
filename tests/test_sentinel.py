"""End-to-end tests exercising OpenMinion 0.1.24 Agent, APIRuntime, @tool, Handoff, and approval_callback."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from openminion import Agent, AgentOutputValidationError

from sentinel.agent import run_repo_triage
from sentinel.models import ReleaseTriageReport
from sentinel.tools import check_release_readiness, inspect_git_repo, scan_secret_leaks


class TestRepoTriageSentinel(unittest.TestCase):
    def test_clean_repo_full_openminion_turn_and_report_write(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "clean_pkg"
            repo.mkdir()
            (repo / "README.md").write_text("# Clean Package\n", encoding="utf-8")
            (repo / "LICENSE").write_text("MIT\n", encoding="utf-8")
            (repo / ".gitignore").write_text(".venv/\n", encoding="utf-8")
            (repo / "test_basic.py").write_text("def test_ok(): assert True\n", encoding="utf-8")

            report_out = Path(td) / "out" / "triage.md"
            approvals: list[str] = []

            def approve_all(tool_name: str, args: dict, approval_id: str) -> bool:
                approvals.append(tool_name)
                return True

            result, diag = run_repo_triage(
                str(repo),
                report_out_path=str(report_out),
                approval_callback=approve_all,
                use_local_demo_llm=True,
            )

            self.assertIsInstance(result.output, ReleaseTriageReport)
            self.assertEqual(result.output.repo_name, "clean_pkg")
            self.assertTrue(result.output.release_ready)
            self.assertEqual(result.output.risk_level, "LOW")
            self.assertEqual(result.output.secret_findings, [])
            self.assertEqual(result.output.checklist_gaps, [])
            self.assertTrue(report_out.exists(), "write_triage_report should persist report when approved")
            self.assertIn("Release Triage Report: clean_pkg", report_out.read_text(encoding="utf-8"))
            self.assertGreaterEqual(diag["builtin_tool_count"], 50)
            self.assertIn("transfer_to_security_specialist", diag["handoff_tools"])
            self.assertGreaterEqual(diag["llm_requests"] or 0, 2)

    def test_dirty_secret_repo_flags_critical_and_blocks_release(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "leaky_pkg"
            repo.mkdir()
            # Synthetic fake token pattern matching aws_access_key rule (NOT a real credential).
            (repo / "config.py").write_text('EXAMPLE = "AKIA1234567890ABCDEF"\n', encoding="utf-8")

            result, _ = run_repo_triage(
                str(repo),
                approval_callback=lambda name, args, aid: True,
                use_local_demo_llm=True,
            )

            self.assertFalse(result.output.release_ready)
            self.assertEqual(result.output.risk_level, "CRITICAL")
            self.assertEqual(len(result.output.secret_findings), 1)
            self.assertEqual(result.output.secret_findings[0].rule, "aws_access_key")
            self.assertGreaterEqual(len(result.output.checklist_gaps), 3)

    def test_approval_callback_blocks_dangerous_write_tool(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "guarded_pkg"
            repo.mkdir()
            (repo / "README.md").write_text("# Guarded\n", encoding="utf-8")
            (repo / "LICENSE").write_text("MIT\n", encoding="utf-8")
            (repo / ".gitignore").write_text(".venv/\n", encoding="utf-8")
            (repo / "test_ok.py").write_text("def test_ok(): pass\n", encoding="utf-8")

            report_out = Path(td) / "blocked" / "triage.md"
            seen_approvals: list[tuple[str, bool]] = []

            def deny_writes(tool_name: str, args: dict, approval_id: str) -> bool:
                allow = tool_name != "write_triage_report"
                seen_approvals.append((tool_name, allow))
                return allow

            # OpenMinion 0.1.24 aborts the turn with plain-text "The action was not run."
            # on callback denial, which triggers AgentOutputValidationError when output_type
            # is a Pydantic model (documented as Finding #6 in SDK_FEEDBACK_REPORT.md).
            with self.assertRaises(AgentOutputValidationError) as ctx:
                run_repo_triage(
                    str(repo),
                    report_out_path=str(report_out),
                    approval_callback=deny_writes,
                    use_local_demo_llm=True,
                )
            self.assertIn("not run", ctx.exception.raw_text.lower())
            self.assertFalse(report_out.exists(), "Denied dangerous tool must not write to disk")
            self.assertTrue(any(name == "write_triage_report" and not ok for name, ok in seen_approvals))

    def test_direct_tools_and_prose_wrapped_json_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "unit_repo"
            repo.mkdir()
            (repo / "README.md").write_text("# Demo\n", encoding="utf-8")

            git_meta = json.loads(inspect_git_repo(str(repo)))
            self.assertEqual(git_meta["repo_name"], "unit_repo")
            sec = json.loads(scan_secret_leaks(str(repo)))
            self.assertTrue(sec["clean"])
            qa = json.loads(check_release_readiness(str(repo)))
            self.assertTrue(qa["has_readme"])
            self.assertFalse(qa["has_license"])

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

    def test_openminion_doctor_cli_json(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "config.json"
            subprocess.run(
                [sys.executable, "-m", "openminion", "--home-root", td, "--data-root", td, "--config", str(cfg), "config", "init"],
                check=True,
                capture_output=True,
            )
            proc = subprocess.run(
                [sys.executable, "-m", "openminion", "--home-root", td, "--data-root", td, "--config", str(cfg), "doctor", "--json"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0)
            payload = json.loads(proc.stdout)
            self.assertIn("checks", payload)
            self.assertGreater(len(payload["checks"]), 0)


if __name__ == "__main__":
    unittest.main()
