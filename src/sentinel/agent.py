"""RepoTriageSentinel — OpenMinion 0.1.24 Python SDK release-readiness & security triage agent."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from openminion import (
    APIRuntime,
    Agent,
    AgentRunResult,
    Handoff,
    MemoryBundle,
    OpenMinionConfig,
    subagent,
)

from sentinel.memory_store import (
    DEFAULT_BUNDLE_FILENAME,
    compute_triage_diff,
    latest_snapshot_for_repo,
    load_triage_history,
    persist_triage_bundle,
)
from sentinel.mock_openai import DeterministicTriageLLMServer
from sentinel.models import ReleaseBrief, ReleaseTriageReport, SecurityAuditVerdict
from sentinel.tools import (
    audit_dependency_and_secret_context,
    check_release_readiness,
    inspect_git_repo,
    scan_secret_leaks,
    scoped_write_root,
    summarize_recent_changes,
    write_triage_report,
)

SENTINEL_INSTRUCTIONS = """You are RepoTriageSentinel, a strict open-source release QA and security auditor.
1. Always call inspect_git_repo, scan_secret_leaks, and check_release_readiness on the target repository path.
2. Always delegate deep dependency and secret-context review via transfer_to_security_specialist.
3. If an output report path is requested, call write_triage_report after analyzing all evidence.
4. Return ONLY a valid JSON object matching ReleaseTriageReport."""

SECURITY_SPECIALIST_INSTRUCTIONS = """You are a focused security reviewer specialist.
Call audit_dependency_and_secret_context on the requested repository path and return ONLY a valid JSON object matching SecurityAuditVerdict."""

RELEASE_BRIEF_INSTRUCTIONS = """You are a bounded release-brief subagent.
Call summarize_recent_changes on the target repository path and return ONLY a valid JSON object matching ReleaseBrief."""


@dataclass(frozen=True)
class ProviderPreset:
    runtime_provider: str
    default_model: str
    default_base_url: str | None
    api_key_env: str
    default_timeout_seconds: int


PROVIDER_PRESETS: dict[str, ProviderPreset] = {
    "cortensor-portal": ProviderPreset(
        runtime_provider="openai",
        default_model="oss-20b",
        default_base_url="https://api.cortensor.app/v1",
        api_key_env="CORTENSOR_API_KEY",
        default_timeout_seconds=480,
    ),
    "cortensor": ProviderPreset(
        runtime_provider="cortensor",
        default_model="gpt-oss-20b",
        default_base_url="http://127.0.0.1:8080/api/v2/completions",
        api_key_env="CORTENSOR_API_KEY",
        default_timeout_seconds=420,
    ),
    "openai": ProviderPreset(
        runtime_provider="openai",
        default_model="gpt-4.1-mini",
        default_base_url="https://api.openai.com/v1",
        api_key_env="OPENAI_API_KEY",
        default_timeout_seconds=120,
    ),
    "openrouter": ProviderPreset(
        runtime_provider="openrouter",
        default_model="openai/gpt-4.1-mini",
        default_base_url="https://openrouter.ai/api/v1",
        api_key_env="OPENROUTER_API_KEY",
        default_timeout_seconds=120,
    ),
    "ollama": ProviderPreset(
        runtime_provider="ollama",
        default_model="llama3.1",
        default_base_url="http://127.0.0.1:11434",
        api_key_env="OLLAMA_API_KEY",
        default_timeout_seconds=180,
    ),
    "anthropic": ProviderPreset(
        runtime_provider="anthropic",
        default_model="claude-sonnet-5",
        default_base_url="https://api.anthropic.com/v1",
        api_key_env="ANTHROPIC_API_KEY",
        default_timeout_seconds=120,
    ),
}


def build_runtime_config(
    *,
    state_dir: Path,
    provider: str = "openai",
    model: str | None = None,
    base_url: str | None = None,
    api_key_env: str | None = None,
    api_key: str = "",
    timeout_seconds: int | None = None,
) -> tuple[OpenMinionConfig, int]:
    """Programmatically build an OpenMinionConfig without shelling out to `openminion config init`.

    Sets `default_channel="console"` explicitly to work around OpenMinion 0.1.24's
    `AgentProfileConfig.default_channel=""` bug under `APIRuntime.from_config(...)`.
    """
    preset = PROVIDER_PRESETS.get(provider, PROVIDER_PRESETS["openai"])
    runtime_provider = preset.runtime_provider
    effective_model = model or preset.default_model
    effective_base_url = base_url or preset.default_base_url
    effective_key_env = api_key_env or preset.api_key_env
    effective_timeout = timeout_seconds or preset.default_timeout_seconds

    state_dir.mkdir(parents=True, exist_ok=True)
    storage_db = (state_dir / "state" / "openminion.db").resolve()

    provider_payload: dict[str, Any] = {
        "model": effective_model,
        "timeout_seconds": effective_timeout,
    }
    if effective_base_url:
        provider_payload["base_url"] = effective_base_url
    if effective_key_env:
        provider_payload["api_key_env"] = effective_key_env
    if api_key:
        provider_payload["api_key"] = api_key

    config_dict: dict[str, Any] = {
        "agents": {
            "openminion": {
                "name": "openminion",
                "provider": runtime_provider,
                "default_channel": "console",
                "system_prompt": SENTINEL_INSTRUCTIONS,
            }
        },
        "storage": {
            "path": str(storage_db),
        },
        "action_policy": {
            "mode": "ask",
            "allow_read_only_without_prompt": True,
        },
        "providers": {
            runtime_provider: provider_payload,
        },
    }
    return OpenMinionConfig.from_dict(config_dict), effective_timeout


def _describe_delta(event: object) -> dict[str, Any]:
    if isinstance(event, dict):
        return {
            "type": "dict",
            "kind": str(event.get("kind") or event.get("event_type") or "event"),
            "tool_name": event.get("tool_name"),
        }
    return {
        "type": type(event).__name__,
        "status_key": getattr(event, "status_key", None),
        "label": getattr(event, "label", None),
    }


def run_repo_triage(
    repo_path: str,
    *,
    provider: str = "openai",
    model: str | None = None,
    base_url: str | None = None,
    api_key: str = "",
    report_out_path: str | None = None,
    write_root_dir: str | Path | None = None,
    approval_callback: Callable[[str, dict[str, Any], str], bool] | None = None,
    on_stream_event: Callable[[dict[str, Any]], None] | None = None,
    state_dir: Path | str | None = None,
    session_id: str | None = None,
    timeout_seconds: int | None = None,
    run_brief_subagent: bool = True,
    use_local_demo_llm: bool = False,
    enable_handoff: bool = True,
) -> tuple[AgentRunResult[ReleaseTriageReport], dict[str, Any]]:
    """Run a full OpenMinion Agent triage turn (with Handoff, subagent, streaming, and MemoryBundle)."""
    resolved_repo_path = Path(repo_path).expanduser().resolve()
    resolved_repo = str(resolved_repo_path)

    tmp_ctx = tempfile.TemporaryDirectory() if state_dir is None else None
    work_dir = Path(tmp_ctx.name) if tmp_ctx is not None else Path(state_dir).expanduser().resolve()

    resolved_report_out: str | None = None
    effective_write_root: Path = resolved_repo_path
    if report_out_path:
        report_target = Path(report_out_path).expanduser().resolve()
        resolved_report_out = str(report_target)
        if write_root_dir is not None:
            effective_write_root = Path(write_root_dir).expanduser().resolve()
        elif report_target.is_relative_to(resolved_repo_path):
            effective_write_root = resolved_repo_path
        else:
            effective_write_root = report_target.parent
    elif write_root_dir is not None:
        effective_write_root = Path(write_root_dir).expanduser().resolve()

    bundle_path = work_dir / DEFAULT_BUNDLE_FILENAME
    prior_items, prior_import_receipt = load_triage_history(bundle_path)
    previous_snapshot = latest_snapshot_for_repo(
        prior_items, repo_name=resolved_repo_path.name, repo_path=resolved_repo
    )

    demo_server: DeterministicTriageLLMServer | None = None
    try:
        effective_provider = provider
        effective_base_url = base_url
        effective_model = model
        effective_key = api_key

        if use_local_demo_llm:
            demo_server = DeterministicTriageLLMServer(
                target_repo=resolved_repo,
                report_out_path=resolved_report_out,
                invoke_handoff=enable_handoff,
            )
            effective_base_url = demo_server.start()
            effective_provider = "openai"
            effective_model = "sentinel-local-test"
            effective_key = "demo-local-key"

        cfg, effective_timeout = build_runtime_config(
            state_dir=work_dir,
            provider=effective_provider,
            model=effective_model,
            base_url=effective_base_url,
            api_key=effective_key,
            timeout_seconds=timeout_seconds,
        )

        rt = APIRuntime.from_config(config=cfg, home_root=work_dir, data_root=work_dir)
        peer_rt: APIRuntime | None = None
        try:
            posture = rt.runtime_posture()
            inventory = rt.tool_inventory_report(readiness=True)

            # OpenMinion 0.1.24 executes Handoff delegate tools on a worker thread while the
            # parent holds ToolRegistry.temporary_registration_scope(), so a Handoff target
            # with decorated @tool functions must use its own dedicated APIRuntime instance.
            handoffs_list: list[Handoff] = []
            if enable_handoff:
                peer_state_dir = work_dir / "peer_security"
                peer_cfg, _ = build_runtime_config(
                    state_dir=peer_state_dir,
                    provider=effective_provider,
                    model=effective_model,
                    base_url=effective_base_url,
                    api_key=effective_key,
                    timeout_seconds=effective_timeout,
                )
                peer_rt = APIRuntime.from_config(
                    config=peer_cfg,
                    home_root=peer_state_dir,
                    data_root=peer_state_dir,
                )
                security_peer = Agent[str, SecurityAuditVerdict](
                    name="security_specialist",
                    instructions=SECURITY_SPECIALIST_INSTRUCTIONS,
                    output_type=SecurityAuditVerdict,
                    runtime=peer_rt,
                    tools=[audit_dependency_and_secret_context],
                )
                handoffs_list = [
                    Handoff(
                        target=security_peer,
                        description=(
                            "Delegate deep dependency, .env, and supply-chain security "
                            "verification to the security specialist."
                        ),
                    )
                ]

            tools_list: list[Any] = [
                inspect_git_repo,
                scan_secret_leaks,
                check_release_readiness,
            ]
            if resolved_report_out:
                tools_list.append(write_triage_report)

            sentinel_agent = Agent[str, ReleaseTriageReport](
                name="repo_triage_sentinel",
                instructions=SENTINEL_INSTRUCTIONS,
                output_type=ReleaseTriageReport,
                runtime=rt,
                tools=tools_list,
                handoffs=handoffs_list,
                session_id=session_id,
            )

            prompt_parts = [f"Audit repository at path: {resolved_repo}"]
            if previous_snapshot is not None:
                prompt_parts.append(
                    "Prior baseline snapshot from MemoryBundle: "
                    f"risk_level={previous_snapshot.get('risk_level')}, "
                    f"secret_count={len(previous_snapshot.get('secret_findings') or [])}, "
                    f"gap_count={len(previous_snapshot.get('checklist_gaps') or [])}."
                )
            if resolved_report_out:
                prompt_parts.append(f"Write Markdown report to: {resolved_report_out}")
            prompt = "\n".join(prompt_parts)

            stream_events: list[dict[str, Any]] = []
            tool_events_seen: list[str] = []

            def _handle_delta(raw_event: object) -> None:
                summary = _describe_delta(raw_event)
                stream_events.append(summary)
                if summary.get("kind") == "tool_completed" and summary.get("tool_name"):
                    tool_events_seen.append(str(summary["tool_name"]))
                if on_stream_event is not None:
                    on_stream_event(summary)

            with scoped_write_root(effective_write_root):
                result = sentinel_agent.run_stream(
                    prompt,
                    session_id=session_id,
                    on_delta=_handle_delta,
                    approval_callback=approval_callback,
                    timeout_seconds=effective_timeout,
                )

            # Bounded OpenMinion subagent for isolated executive release-brief synthesis.
            subagent_context_id: str | None = None
            subagent_executed = False
            if run_brief_subagent:
                brief_child = subagent(
                    sentinel_agent,
                    name="release_brief_writer",
                    instructions=RELEASE_BRIEF_INSTRUCTIONS,
                    tools=[summarize_recent_changes],
                    output_type=ReleaseBrief,
                    timeout_seconds=min(effective_timeout, 120),
                )
                brief_res = brief_child.run(
                    f"Draft an executive release brief for repository: {resolved_repo}",
                    timeout_seconds=min(effective_timeout, 120),
                )
                subagent_executed = True
                if brief_child.subagent_context is not None:
                    subagent_context_id = brief_child.subagent_context.context_id
                result.output.release_brief = brief_res.output

            # Cross-run MemoryBundle diffing and persistence.
            diff_summary = compute_triage_diff(previous_snapshot, result.output)
            result.output.diff_from_previous = diff_summary
            bundle, saved_receipt = persist_triage_bundle(
                bundle_path,
                prior_items,
                result.output,
                repo_path=resolved_repo,
                run_id=result.run_id,
                session_id=result.session_id,
            )

            handoff_executed = (
                "transfer_to_security_specialist" in tool_events_seen
                or (demo_server is not None and demo_server.handoff_calls > 0)
                or result.output.security_specialist_verdict is not None
            )

            diagnostics = {
                "runtime_mode": posture.get("runtime_mode"),
                "brain_bridge_active": posture.get("brain_bridge_active"),
                "provider_preset": effective_provider,
                "timeout_seconds": effective_timeout,
                "builtin_tool_count": len(inventory),
                "registered_custom_tools": [
                    t for t in sentinel_agent.tools if not t.startswith("transfer_to_")
                ],
                "handoff_tools": list(sentinel_agent.handoff_tool_names),
                "handoff_executed": handoff_executed,
                "subagent_executed": subagent_executed,
                "subagent_context_id": subagent_context_id,
                "stream_events_count": len(stream_events),
                "completed_tools_streamed": tool_events_seen,
                "memory_bundle_version": bundle.version or MemoryBundle.version,
                "memory_bundle_prior_items": (
                    prior_import_receipt["item_count"] if prior_import_receipt else 0
                ),
                "memory_bundle_saved_items": saved_receipt["item_count"],
                "memory_bundle_path": str(bundle_path) if state_dir is not None else None,
                "diff_trend": diff_summary.trend,
                "llm_requests": len(demo_server.requests) if demo_server else None,
                "submit_output_calls": (
                    demo_server.submit_output_calls if demo_server else None
                ),
            }
            return result, diagnostics
        finally:
            if peer_rt is not None:
                peer_rt.close()
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
    parser.add_argument(
        "--provider",
        default="cortensor-portal",
        choices=sorted(PROVIDER_PRESETS.keys()),
        help="LLM provider preset (default: cortensor-portal)",
    )
    parser.add_argument("--model", default=None, help="Override LLM model name")
    parser.add_argument(
        "--base-url",
        default=os.environ.get("OPENMINION_BASE_URL"),
        help="Custom API base URL override",
    )
    parser.add_argument(
        "--report-out",
        default=None,
        help="Optional Markdown report output path (requires --auto-approve to write)",
    )
    parser.add_argument(
        "--state-dir",
        default=None,
        help="Durable OpenMinion state & MemoryBundle directory for cross-run diffing",
    )
    parser.add_argument(
        "--session-id",
        default=None,
        help="Optional explicit OpenMinion session ID to resume across runs",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Override turn timeout in seconds (defaults to 480s for cortensor-portal, 420s for cortensor)",
    )
    parser.add_argument(
        "--auto-approve",
        action="store_true",
        help="Approve dangerous write_triage_report tool calls automatically",
    )
    parser.add_argument(
        "--stream",
        action="store_true",
        help="Print live OpenMinion run_stream progress events to stderr",
    )
    parser.add_argument(
        "--no-subagent",
        action="store_true",
        help="Skip the bounded release_brief_writer subagent step",
    )
    parser.add_argument(
        "--demo-local",
        action="store_true",
        help="Run offline against deterministic local OpenAI-compatible server",
    )
    args = parser.parse_args(argv)

    approvals: list[tuple[str, bool]] = []

    def _approve(tool_name: str, tool_args: dict[str, Any], approval_id: str) -> bool:
        del tool_args, approval_id
        if tool_name == "write_triage_report":
            allowed = bool(args.auto_approve)
        elif tool_name.startswith("transfer_to_"):
            allowed = True
        else:
            allowed = bool(args.auto_approve)
        approvals.append((tool_name, allowed))
        return allowed

    def _emit_stream(ev: dict[str, Any]) -> None:
        if args.stream:
            label = ev.get("label") or ev.get("tool_name") or ev.get("kind") or ev.get("type")
            print(f"[stream] {ev.get('type')}: {label}", file=sys.stderr)

    result, diag = run_repo_triage(
        args.repo_path,
        provider=args.provider,
        model=args.model,
        base_url=args.base_url,
        report_out_path=args.report_out,
        approval_callback=_approve,
        on_stream_event=_emit_stream if args.stream else None,
        state_dir=args.state_dir,
        session_id=args.session_id,
        timeout_seconds=args.timeout,
        run_brief_subagent=not args.no_subagent,
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
