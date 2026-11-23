"""Local deterministic OpenAI-compatible HTTP server for offline OpenMinion E2E demos & tests.

Implements POST /v1/chat/completions with:
1. Schema-compliant handling of OpenMinion's internal `submit_output` structured-output calls
   (avoiding schema-validation retries during offline CI runs).
2. Real tool_calls across all three OpenMinion agent roles:
   - Main `repo_triage_sentinel` (read-only tools -> Handoff `transfer_to_security_specialist`
     -> optional dangerous `write_triage_report` -> strict `ReleaseTriageReport` JSON).
   - Delegated `security_specialist` Handoff peer (`audit_dependency_and_secret_context`
     -> strict `SecurityAuditVerdict` JSON).
   - Bounded `release_brief_writer` subagent (`summarize_recent_changes`
     -> strict `ReleaseBrief` JSON).
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class DeterministicTriageLLMServer:
    """In-process OpenAI-compatible server driving a multi-agent RepoTriageSentinel workflow."""

    def __init__(
        self,
        target_repo: str,
        report_out_path: str | None = None,
        *,
        invoke_handoff: bool = True,
    ) -> None:
        self.target_repo = target_repo
        self.report_out_path = report_out_path
        self.invoke_handoff = invoke_handoff
        self.requests: list[dict[str, Any]] = []
        self.submit_output_calls: int = 0
        self.handoff_calls: int = 0
        self.subagent_calls: int = 0
        self.observed_results: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        assert self._server is not None
        host, port = self._server.server_address
        return f"http://{host}:{port}/v1"

    def start(self) -> str:
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length).decode("utf-8")
                body = json.loads(raw)
                with parent._lock:
                    parent.requests.append(body)
                    resp = parent._build_response(body)
                encoded = json.dumps(resp).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.base_url

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def __enter__(self) -> "DeterministicTriageLLMServer":
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()

    @staticmethod
    def _unwrap_tool_content(content: Any) -> dict[str, Any]:
        if isinstance(content, str):
            try:
                parsed = json.loads(content)
            except json.JSONDecodeError:
                return {"raw": content}
        elif isinstance(content, dict):
            parsed = content
        else:
            return {"raw": str(content)}

        if isinstance(parsed, dict) and isinstance(parsed.get("outputs"), dict):
            raw_data = parsed["outputs"].get("data")
            if isinstance(raw_data, str):
                try:
                    decoded = json.loads(raw_data)
                    if isinstance(decoded, dict):
                        return decoded
                except json.JSONDecodeError:
                    return {"raw": raw_data}
            elif isinstance(raw_data, dict):
                return raw_data
        return parsed if isinstance(parsed, dict) else {"raw": parsed}

    def _extract_turn_tool_results(
        self, messages: list[dict[str, Any]]
    ) -> dict[str, dict[str, Any]]:
        turn_results: dict[str, dict[str, Any]] = {}
        call_id_to_name: dict[str, str] = {}

        for msg in messages:
            if msg.get("role") == "assistant":
                for tc in msg.get("tool_calls") or []:
                    if isinstance(tc, dict):
                        cid = str(tc.get("id") or "")
                        fn = str((tc.get("function") or {}).get("name") or "")
                        if cid and fn:
                            call_id_to_name[cid] = fn
            elif msg.get("role") == "tool":
                name = str(msg.get("name") or "")
                if not name:
                    cid = str(msg.get("tool_call_id") or "")
                    name = call_id_to_name.get(cid, "")
                inner = self._unwrap_tool_content(msg.get("content") or "{}")
                if not name:
                    if "manifests" in inner:
                        name = "inspect_git_repo"
                    elif "files_scanned" in inner:
                        name = "scan_secret_leaks"
                    elif "has_readme" in inner:
                        name = "check_release_readiness"
                    elif "committed_env_files" in inner:
                        name = "audit_dependency_and_secret_context"
                    elif "top_level_entries" in inner:
                        name = "summarize_recent_changes"
                    elif "output" in inner and isinstance(inner.get("output"), dict) and "specialist_name" in inner["output"]:
                        name = "transfer_to_security_specialist"
                    elif "written" in inner:
                        name = "write_triage_report"
                if name:
                    turn_results[name] = inner
        return turn_results

    def _handle_submit_output(
        self,
        tool_spec: dict[str, Any],
        messages: list[dict[str, Any]],
    ) -> dict[str, Any]:
        self.submit_output_calls += 1
        params = (tool_spec.get("function") or {}).get("parameters") or {}
        props = params.get("properties") or {}
        args: dict[str, Any] = {}

        for key, spec in props.items():
            if not isinstance(spec, dict):
                args[key] = "ok"
                continue
            enum_vals = spec.get("enum")
            ftype = spec.get("type")
            if enum_vals:
                args[key] = enum_vals[0]
            elif ftype == "boolean":
                args[key] = False
            elif ftype in ("integer", "number"):
                args[key] = 0
            elif ftype == "array":
                args[key] = []
            elif ftype == "object":
                args[key] = {}
            else:
                args[key] = "ok"

        # Populate semantically accurate answers for OpenMinion's internal brain classifiers.
        if "needs_live_data" in props:
            args["needs_live_data"] = False
        if "time_sensitive" in props:
            args["time_sensitive"] = False
        if "confidence" in props and isinstance(props["confidence"], dict):
            if props["confidence"].get("type") in ("number", "integer"):
                args["confidence"] = 1.0
        if "status" in props and isinstance(props["status"], dict):
            enum_vals = props["status"].get("enum") or []
            if "complete" in enum_vals:
                args["status"] = "complete"
            elif "completed" in enum_vals:
                args["status"] = "completed"
        if "satisfied" in props:
            args["satisfied"] = True
        if "next_action" in props and isinstance(props["next_action"], dict):
            enum_vals = props["next_action"].get("enum") or []
            for preferred in ("respond", "finish", "complete", "none"):
                if preferred in enum_vals:
                    args["next_action"] = preferred
                    break
        if "final_answer" in props:
            # Echo back the most recent synthesized assistant JSON when OpenMinion's final judge asks for it.
            last_json = ""
            for msg in reversed(messages):
                content = str(msg.get("content") or "").strip()
                if content.startswith("{") and content.endswith("}"):
                    last_json = content
                    break
            args["final_answer"] = last_json or json.dumps(
                self._synthesize_report(self.observed_results), ensure_ascii=True
            )

        return self._wrap_choice(
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": f"call_submit_output_{self.submit_output_calls}",
                        "type": "function",
                        "function": {
                            "name": "submit_output",
                            "arguments": json.dumps(args, ensure_ascii=True),
                        },
                    }
                ],
            },
            finish_reason="tool_calls",
        )

    def _build_response(self, body: dict[str, Any]) -> dict[str, Any]:
        messages = body.get("messages", [])
        tools = [t for t in (body.get("tools") or []) if isinstance(t, dict)]
        available_tool_names = [
            str((t.get("function") or {}).get("name") or "") for t in tools
        ]
        available_set = set(available_tool_names)

        # Handle OpenMinion's internal structured-output classifiers cleanly without retry noise.
        if available_tool_names == ["submit_output"]:
            return self._handle_submit_output(tools[0], messages)

        turn_results = self._extract_turn_tool_results(messages)
        self.observed_results.update(turn_results)

        # Role A: Delegated security_specialist Handoff peer.
        if "audit_dependency_and_secret_context" in available_set:
            if "audit_dependency_and_secret_context" not in turn_results:
                return self._wrap_choice(
                    {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_security_context_1",
                                "type": "function",
                                "function": {
                                    "name": "audit_dependency_and_secret_context",
                                    "arguments": json.dumps({"repo_path": self.target_repo}),
                                },
                            }
                        ],
                    },
                    finish_reason="tool_calls",
                )
            sec_ctx = turn_results["audit_dependency_and_secret_context"]
            verdict_payload = {
                "specialist_name": "security_specialist",
                "files_reviewed": int(sec_ctx.get("files_reviewed", 0)),
                "committed_env_files": list(sec_ctx.get("committed_env_files") or []),
                "dependency_risks": list(sec_ctx.get("dependency_risks") or []),
                "verdict": str(sec_ctx.get("verdict") or "CLEAR"),
                "notes": (
                    f"Reviewed {sec_ctx.get('files_reviewed', 0)} file(s); "
                    f"committed_env={len(sec_ctx.get('committed_env_files') or [])}, "
                    f"dependency_risks={len(sec_ctx.get('dependency_risks') or [])}."
                ),
            }
            return self._wrap_choice(
                {
                    "role": "assistant",
                    "content": json.dumps(verdict_payload, ensure_ascii=True),
                },
                finish_reason="stop",
            )

        # Role B: Bounded release_brief_writer subagent.
        if "summarize_recent_changes" in available_set:
            self.subagent_calls += 1
            if "summarize_recent_changes" not in turn_results:
                return self._wrap_choice(
                    {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_summarize_changes_1",
                                "type": "function",
                                "function": {
                                    "name": "summarize_recent_changes",
                                    "arguments": json.dumps({"repo_path": self.target_repo}),
                                },
                            }
                        ],
                    },
                    finish_reason="tool_calls",
                )
            summary_data = turn_results["summarize_recent_changes"]
            commits = list(summary_data.get("recent_commits") or [])
            entries = list(summary_data.get("top_level_entries") or [])
            highlights = commits[:4] if commits else [f"Repository layout contains: {', '.join(entries[:6])}"]
            brief_payload = {
                "repo_name": str(summary_data.get("repo_name") or "target-repo"),
                "recent_commit_count": int(summary_data.get("recent_commit_count", 0)),
                "change_highlights": highlights,
                "release_recommendation": (
                    "Proceed to release tagging only after confirming zero CRITICAL secret leaks and specialist CLEAR status."
                ),
            }
            return self._wrap_choice(
                {
                    "role": "assistant",
                    "content": json.dumps(brief_payload, ensure_ascii=True),
                },
                finish_reason="stop",
            )

        # Role C: Main RepoTriageSentinel orchestrator.
        # Step 1: Call all three READ_ONLY triage tools.
        pending_calls: list[dict[str, Any]] = []
        for idx, tname in enumerate(
            ("inspect_git_repo", "scan_secret_leaks", "check_release_readiness"), start=1
        ):
            if tname in available_set and tname not in turn_results:
                pending_calls.append(
                    {
                        "id": f"call_{tname}_{idx}",
                        "type": "function",
                        "function": {
                            "name": tname,
                            "arguments": json.dumps({"repo_path": self.target_repo}),
                        },
                    }
                )
        if pending_calls:
            return self._wrap_choice(
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": pending_calls,
                },
                finish_reason="tool_calls",
            )

        # Step 2: Execute real OpenMinion Handoff to security_specialist.
        if (
            self.invoke_handoff
            and "transfer_to_security_specialist" in available_set
            and "transfer_to_security_specialist" not in turn_results
        ):
            self.handoff_calls += 1
            return self._wrap_choice(
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_handoff_security_specialist",
                            "type": "function",
                            "function": {
                                "name": "transfer_to_security_specialist",
                                "arguments": json.dumps(
                                    {
                                        "message": f"Perform deep dependency and secret-context audit on {self.target_repo}"
                                    }
                                ),
                            },
                        }
                    ],
                },
                finish_reason="tool_calls",
            )

        # Step 3: Optionally write Markdown report (triggers dangerous=True approval_callback).
        if (
            self.report_out_path
            and "write_triage_report" in available_set
            and "write_triage_report" not in turn_results
        ):
            md = self._render_markdown(self.observed_results)
            return self._wrap_choice(
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_write_report",
                            "type": "function",
                            "function": {
                                "name": "write_triage_report",
                                "arguments": json.dumps(
                                    {
                                        "output_path": self.report_out_path,
                                        "markdown_body": md,
                                    }
                                ),
                            },
                        }
                    ],
                },
                finish_reason="tool_calls",
            )

        # Step 4: Emit final strict ReleaseTriageReport JSON.
        report_obj = self._synthesize_report(self.observed_results)
        return self._wrap_choice(
            {
                "role": "assistant",
                "content": json.dumps(report_obj, ensure_ascii=True),
            },
            finish_reason="stop",
        )

    def _synthesize_report(self, results: dict[str, dict[str, Any]]) -> dict[str, Any]:
        git_data = results.get("inspect_git_repo", {})
        sec_data = results.get("scan_secret_leaks", {})
        qa_data = results.get("check_release_readiness", {})
        handoff_raw = results.get("transfer_to_security_specialist", {})
        specialist_out = (
            handoff_raw.get("output")
            if isinstance(handoff_raw.get("output"), dict)
            else results.get("audit_dependency_and_secret_context", {})
        )

        repo_name = str(git_data.get("repo_name") or sec_data.get("repo_name") or "target-repo")
        findings = list(sec_data.get("findings") or [])
        gaps = list(qa_data.get("gaps") or [])
        dep_risks = list(specialist_out.get("dependency_risks") or [])
        specialist_verdict = (
            str(specialist_out.get("verdict"))
            if specialist_out.get("verdict")
            else None
        )

        if findings or specialist_verdict == "BLOCK_RELEASE":
            risk = "CRITICAL"
            ready = False
        elif len(gaps) >= 2:
            risk = "HIGH"
            ready = False
        elif gaps or dep_risks or specialist_verdict == "REVIEW_REQUIRED":
            risk = "MEDIUM"
            ready = False
        else:
            risk = "LOW"
            ready = True

        actions: list[str] = []
        if findings:
            actions.append(
                f"Rotate and scrub {len(findings)} detected secret pattern(s) before publishing."
            )
        for risk_item in dep_risks:
            actions.append(
                f"Resolve {risk_item.get('severity', 'MEDIUM')} risk in {risk_item.get('manifest', 'manifest')}: {risk_item.get('issue', '')}."
            )
        for gap in gaps:
            actions.append(f"Resolve checklist gap: {gap}.")
        if not actions:
            actions.append("All release hygiene, secret, and specialist checks passed; safe to tag release.")

        summary = (
            f"Repo '{repo_name}' scanned {sec_data.get('files_scanned', 0)} file(s) "
            f"with {len(findings)} secret finding(s), {len(gaps)} checklist gap(s), "
            f"and {len(dep_risks)} specialist risk(s) (specialist={specialist_verdict or 'N/A'}). "
            f"Risk level: {risk}."
        )
        return {
            "repo_name": repo_name,
            "release_ready": ready,
            "risk_level": risk,
            "secret_findings": findings,
            "checklist_gaps": gaps,
            "dependency_risks": dep_risks,
            "security_specialist_verdict": specialist_verdict,
            "recommended_actions": actions,
            "summary": summary,
        }

    def _render_markdown(self, results: dict[str, dict[str, Any]]) -> str:
        rep = self._synthesize_report(results)
        lines = [
            f"# Release Triage Report: {rep['repo_name']}",
            "",
            f"- **Release Ready:** `{rep['release_ready']}`",
            f"- **Risk Level:** `{rep['risk_level']}`",
            f"- **Secret Findings:** {len(rep['secret_findings'])}",
            f"- **Checklist Gaps:** {len(rep['checklist_gaps'])}",
            f"- **Specialist Verdict:** `{rep['security_specialist_verdict'] or 'N/A'}`",
            f"- **Dependency Risks:** {len(rep['dependency_risks'])}",
            "",
            "## Summary",
            "",
            rep["summary"],
            "",
        ]
        return "\n".join(lines)

    @staticmethod
    def _wrap_choice(message: dict[str, Any], *, finish_reason: str) -> dict[str, Any]:
        return {
            "id": "chatcmpl-openminion-sentinel",
            "object": "chat.completion",
            "created": 1763865600,
            "model": "sentinel-local-test",
            "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
            "usage": {"prompt_tokens": 120, "completion_tokens": 64, "total_tokens": 184},
        }
