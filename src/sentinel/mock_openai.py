"""Local deterministic OpenAI-compatible HTTP server for offline OpenMinion E2E demos & tests.

Implements POST /v1/chat/completions with real OpenAI tool_calls so OpenMinion's
`openai` provider executes the complete HTTP -> tool registry -> approval_callback ->
tool execution -> structured Pydantic output_type pipeline without external API keys.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class DeterministicTriageLLMServer:
    """In-process OpenAI-compatible server driving a multi-step RepoTriageSentinel workflow."""

    def __init__(self, target_repo: str, report_out_path: str | None = None) -> None:
        self.target_repo = target_repo
        self.report_out_path = report_out_path
        self.requests: list[dict[str, Any]] = []
        self.observed_results: dict[str, dict[str, Any]] = {}
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

    def _build_response(self, body: dict[str, Any]) -> dict[str, Any]:
        messages = body.get("messages", [])
        tool_results: dict[str, dict[str, Any]] = dict(self.observed_results)
        seen_tools: set[str] = set(self.observed_results.keys())

        for msg in messages:
            if msg.get("role") == "tool":
                name = str(msg.get("name") or "")
                content = msg.get("content") or "{}"
                if isinstance(content, str):
                    try:
                        parsed = json.loads(content)
                    except json.JSONDecodeError:
                        parsed = {"raw": content}
                else:
                    parsed = {"raw": content}

                # Unwrap OpenMinion's {"status": "success", "outputs": {"data": "<json>"}} envelope.
                inner = parsed
                if isinstance(parsed, dict) and isinstance(parsed.get("outputs"), dict):
                    raw_data = parsed["outputs"].get("data")
                    if isinstance(raw_data, str):
                        try:
                            inner = json.loads(raw_data)
                        except json.JSONDecodeError:
                            inner = {"raw": raw_data}
                    elif isinstance(raw_data, dict):
                        inner = raw_data

                if name:
                    seen_tools.add(name)
                    tool_results[name] = inner
                elif isinstance(inner, dict):
                    if "manifests" in inner:
                        seen_tools.add("inspect_git_repo")
                        tool_results["inspect_git_repo"] = inner
                    elif "files_scanned" in inner:
                        seen_tools.add("scan_secret_leaks")
                        tool_results["scan_secret_leaks"] = inner
                    elif "has_readme" in inner:
                        seen_tools.add("check_release_readiness")
                        tool_results["check_release_readiness"] = inner
                    elif "written" in inner or "denied" in str(content).lower() or "reject" in str(content).lower() or "cancel" in str(content).lower():
                        seen_tools.add("write_triage_report")
                        tool_results["write_triage_report"] = inner

        self.observed_results.update(tool_results)

        available_tool_names = {
            t.get("function", {}).get("name")
            for t in body.get("tools", [])
            if isinstance(t, dict)
        }

        # Step 1: Call read-only triage tools in parallel/sequence.
        pending_calls: list[dict[str, Any]] = []
        for idx, tname in enumerate(
            ("inspect_git_repo", "scan_secret_leaks", "check_release_readiness"), start=1
        ):
            if tname in available_tool_names and tname not in seen_tools:
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

        # Step 2: Optionally write report (triggers dangerous=True approval_callback).
        if (
            self.report_out_path
            and "write_triage_report" in available_tool_names
            and "write_triage_report" not in seen_tools
        ):
            md = self._render_markdown(tool_results)
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

        # Step 3: Emit final strict ReleaseTriageReport JSON.
        report_obj = self._synthesize_report(tool_results)
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

        repo_name = str(git_data.get("repo_name") or sec_data.get("repo_name") or "target-repo")
        findings = list(sec_data.get("findings") or [])
        gaps = list(qa_data.get("gaps") or [])

        if findings:
            risk = "CRITICAL"
            ready = False
        elif len(gaps) >= 2:
            risk = "HIGH"
            ready = False
        elif gaps:
            risk = "MEDIUM"
            ready = False
        else:
            risk = "LOW"
            ready = True

        actions: list[str] = []
        if findings:
            actions.append(f"Rotate and scrub {len(findings)} detected secret pattern(s) before publishing.")
        for gap in gaps:
            actions.append(f"Resolve checklist gap: {gap}.")
        if not actions:
            actions.append("All release hygiene and secret checks passed; safe to tag release.")

        summary = (
            f"Repo '{repo_name}' scanned {sec_data.get('files_scanned', 0)} files "
            f"with {len(findings)} secret finding(s) and {len(gaps)} checklist gap(s). "
            f"Risk level: {risk}."
        )
        return {
            "repo_name": repo_name,
            "release_ready": ready,
            "risk_level": risk,
            "secret_findings": findings,
            "checklist_gaps": gaps,
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
