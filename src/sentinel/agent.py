"""RepoTriageSentinel — OpenMinion 0.1.24 Python SDK release-readiness & security triage agent."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

from openminion import APIRuntime, Agent, AgentRunResult, Handoff, MemoryBundle

from sentinel.mock_openai import DeterministicTriageLLMServer
from sentinel.models import ReleaseTriageReport
from sentinel.tools import (
    check_release_readiness,
    inspect_git_repo,
    scan_secret_leaks,
    write_triage_report,
)

SENTINEL_INSTRUCTIONS = """You are RepoTriageSentinel, a strict open-source release QA and security auditor.
Always call inspect_git_repo, scan_secret_leaks, and check_release_readiness on the target repository path.
If an output report path is requested, also call write_triage_report after analyzing the evidence.
Return ONLY a valid JSON object matching ReleaseTriageReport."""

SECURITY_SPECIALIST_INSTRUCTIONS = """You are a focused security reviewer specialist.
Call scan_secret_leaks on the requested repository path and return a concise risk verdict."""


def bootstrap_runtime_config(
    *,
    state_dir: Path,
    provider: str = "openai",
    model: str = "gpt-4.1-mini",
    base_url: str | None = None,
    api_key_env: str = "OPENAI_API_KEY",
    api_key: str = "",
) -> Path:
    """Create a canonical OpenMinion 0.1.24 JSON config via `openminion config init` and patch provider settings."""
    state_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = state_dir / "config.json"
    if not cfg_path.exists():
        subprocess.run(
            [
                sys.executable,
                "-m",
                "openminion",
                "--home-root",
                str(state_dir),
                "--data-root",
                str(state_dir),
                "--config",
                str(cfg_path),
                "config",
                "init",
            ],
            check=True,
            capture_output=True,
            text=True,
        )

    data = json.loads(cfg_path.read_text(encoding="utf-8"))
    data.setdefault("agents", {}).setdefault("openminion", {})
    data["agents"]["openminion"]["provider"] = provider
    data["agents"]["openminion"]["system_prompt"] = SENTINEL_INSTRUCTIONS

    # Require explicit approval on dangerous write tools so approval_callback is exercised cleanly.
    data.setdefault("action_policy", {})
    data["action_policy"]["mode"] = "ask"
    data["action_policy"]["allow_read_only_without_prompt"] = True

    prov_cfg = data.setdefault("providers", {}).setdefault(provider, {})
    prov_cfg["model"] = model
    if base_url:
        prov_cfg["base_url"] = base_url
    if api_key_env:
        prov_cfg["api_key_env"] = api_key_env
    if api_key:
        prov_cfg["api_key"] = api_key

    cfg_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return cfg_path


def run_repo_triage(
    repo_path: str,
    *,
    provider: str = "openai",
    model: str | None = None,
    base_url: str | None = None,
    api_key: str = "",
    report_out_path: str | None = None,
    approval_callback: Callable[[str, dict[str, Any], str], bool] | None = None,
    state_dir: Path | None = None,
    use_local_demo_llm: bool = False,
) -> tuple[AgentRunResult[ReleaseTriageReport], dict[str, Any]]:
    """Run a full OpenMinion Agent triage turn and return (typed_result, runtime_diagnostics)."""
    resolved_repo = str(Path(repo_path).expanduser().resolve())
    tmp_ctx = tempfile.TemporaryDirectory() if state_dir is None else None
    work_dir = Path(tmp_ctx.name) if tmp_ctx is not None else state_dir
    assert work_dir is not None

    demo_server: DeterministicTriageLLMServer | None = None
    try:
        effective_provider = provider
        effective_base_url = base_url
        effective_model = model or ("gpt-oss-20b" if provider == "cortensor" else "gpt-4.1-mini")
        effective_key = api_key

        if use_local_demo_llm:
            demo_server = DeterministicTriageLLMServer(
                target_repo=resolved_repo,
                report_out_path=report_out_path,
            )
            effective_base_url = demo_server.start()
            effective_provider = "openai"
            effective_model = "sentinel-local-test"
            effective_key = "demo-local-key"

        cfg_path = bootstrap_runtime_config(
            state_dir=work_dir,
            provider=effective_provider,
            model=effective_model,
            base_url=effective_base_url,
            api_key_env="CORTENSOR_API_KEY" if effective_provider == "cortensor" else "OPENAI_API_KEY",
            api_key=effective_key,
        )

        rt = APIRuntime.from_config_path(str(cfg_path), home_root=work_dir, data_root=work_dir)
        try:
            posture = rt.runtime_posture()
            inventory = rt.tool_inventory_report(readiness=True)

            # Build a specialist peer agent wired via OpenMinion Handoff.
            security_peer = Agent[str, str](
                name="security_specialist",
                instructions=SECURITY_SPECIALIST_INSTRUCTIONS,
                runtime=rt,
                tools=[scan_secret_leaks],
            )

            tools_list = [inspect_git_repo, scan_secret_leaks, check_release_readiness]
            if report_out_path:
                tools_list.append(write_triage_report)

            sentinel_agent = Agent[str, ReleaseTriageReport](
                name="repo_triage_sentinel",
                instructions=SENTINEL_INSTRUCTIONS,
                output_type=ReleaseTriageReport,
                runtime=rt,
                tools=tools_list,
                handoffs=[
                    Handoff(
                        target=security_peer,
                        description="Delegate deep secret-leak verification to the security specialist.",
                    )
                ],
            )

            prompt = f"Audit repository at path: {resolved_repo}"
            if report_out_path:
                prompt += f"\nWrite Markdown report to: {report_out_path}"

            result = sentinel_agent.run(
                prompt,
                approval_callback=approval_callback,
                timeout_seconds=60,
            )

            diagnostics = {
                "runtime_mode": posture.get("runtime_mode"),
                "brain_bridge_active": posture.get("brain_bridge_active"),
                "builtin_tool_count": len(inventory),
                "registered_custom_tools": [t for t in sentinel_agent.tools if not t.startswith("transfer_to_")],
                "handoff_tools": list(sentinel_agent.handoff_tool_names),
                "memory_bundle_version": getattr(MemoryBundle, "version", "available"),
                "llm_requests": len(demo_server.requests) if demo_server else None,
            }
            return result, diagnostics
        finally:
            rt.close()
    finally:
        if demo_server is not None:
            demo_server.stop()
        if tmp_ctx is not None:
            tmp_ctx.cleanup()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="repo-sentinel",
        description="OpenMinion 0.1.24 release readiness & secret-leak triage agent.",
    )
    parser.add_argument("repo_path", help="Local path to the repository to audit")
    parser.add_argument("--provider", default="openai", choices=["openai", "cortensor", "ollama", "openrouter"])
    parser.add_argument("--model", default=None, help="Override LLM model name")
    parser.add_argument("--base-url", default=os.environ.get("OPENMINION_BASE_URL"), help="Custom API base URL")
    parser.add_argument("--report-out", default=None, help="Optional Markdown report output path")
    parser.add_argument("--auto-approve", action="store_true", help="Approve dangerous write_triage_report tool calls")
    parser.add_argument("--demo-local", action="store_true", help="Run against deterministic local OpenAI-compatible server")
    args = parser.parse_args(argv)

    approvals: list[tuple[str, bool]] = []

    def _approve(tool_name: str, tool_args: dict[str, Any], approval_id: str) -> bool:
        allowed = bool(args.auto_approve)
        approvals.append((tool_name, allowed))
        return allowed

    result, diag = run_repo_triage(
        args.repo_path,
        provider=args.provider,
        model=args.model,
        base_url=args.base_url,
        report_out_path=args.report_out,
        approval_callback=_approve,
        use_local_demo_llm=args.demo_local,
    )

    output = {
        "triage": result.output.model_dump(),
        "run_id": result.run_id,
        "session_id": result.session_id,
        "approvals": approvals,
        "diagnostics": diag,
    }
    print(json.dumps(output, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
