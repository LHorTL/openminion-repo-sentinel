"""Real OpenMinion MemoryBundle persistence and cross-run triage diffing."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from openminion.modules.memory.portability import (
    MemoryBundle,
    export_bundle,
    import_bundle,
    load_bundle,
    save_bundle,
)

from sentinel.models import ReleaseTriageReport, TriageDiffSummary

DEFAULT_BUNDLE_FILENAME = "triage_memory_bundle.json"


def _secret_key(item: dict[str, Any]) -> str:
    return f"{item.get('file', '')}:{item.get('line', 0)}:{item.get('rule', '')}"


def load_triage_history(
    bundle_path: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Load and validate an existing OpenMinion MemoryBundle snapshot from disk."""
    if not bundle_path.is_file():
        return [], None
    bundle = load_bundle(bundle_path)
    receipt = import_bundle(bundle, trust_mode="direct")
    return list(bundle.items), receipt


def latest_snapshot_for_repo(
    items: list[dict[str, Any]],
    *,
    repo_name: str,
    repo_path: str,
) -> dict[str, Any] | None:
    """Return the most recent prior triage snapshot matching repo_path or repo_name."""
    for entry in reversed(items):
        if entry.get("repo_path") == repo_path or entry.get("repo_name") == repo_name:
            return entry
    return None


def compute_triage_diff(
    previous: dict[str, Any] | None,
    current: ReleaseTriageReport,
) -> TriageDiffSummary:
    """Compute a deterministic cross-run delta between the prior MemoryBundle snapshot and current report."""
    if previous is None:
        return TriageDiffSummary(has_previous_run=False, trend="baseline")

    prev_secrets = {
        _secret_key(f) for f in (previous.get("secret_findings") or []) if isinstance(f, dict)
    }
    curr_secrets = {
        _secret_key(f.model_dump()) for f in current.secret_findings
    }
    prev_gaps = set(previous.get("checklist_gaps") or [])
    curr_gaps = set(current.checklist_gaps)

    new_secrets = sorted(curr_secrets - prev_secrets)
    resolved_secrets = sorted(prev_secrets - curr_secrets)
    new_gaps = sorted(curr_gaps - prev_gaps)
    resolved_gaps = sorted(prev_gaps - curr_gaps)

    if new_secrets or (new_gaps and not resolved_secrets and len(new_gaps) > len(resolved_gaps)):
        trend = "regressed"
    elif resolved_secrets or (resolved_gaps and not new_secrets and len(resolved_gaps) > len(new_gaps)):
        trend = "improved"
    elif new_gaps and resolved_gaps:
        trend = "regressed" if len(new_gaps) > len(resolved_gaps) else "improved"
    else:
        trend = "unchanged"

    return TriageDiffSummary(
        has_previous_run=True,
        previous_run_id=previous.get("run_id"),
        previous_timestamp=previous.get("timestamp"),
        new_secrets=new_secrets,
        resolved_secrets=resolved_secrets,
        new_gaps=new_gaps,
        resolved_gaps=resolved_gaps,
        trend=trend,
    )


def persist_triage_bundle(
    bundle_path: Path,
    prior_items: list[dict[str, Any]],
    report: ReleaseTriageReport,
    *,
    repo_path: str,
    run_id: str | None,
    session_id: str | None,
) -> tuple[MemoryBundle, dict[str, Any]]:
    """Append the current triage snapshot and persist an OpenMinion MemoryBundle JSON file."""
    snapshot = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "session_id": session_id,
        "repo_name": report.repo_name,
        "repo_path": repo_path,
        "release_ready": report.release_ready,
        "risk_level": report.risk_level,
        "secret_findings": [f.model_dump() for f in report.secret_findings],
        "checklist_gaps": list(report.checklist_gaps),
        "dependency_risks": [r.model_dump() for r in report.dependency_risks],
        "security_specialist_verdict": report.security_specialist_verdict,
    }
    updated_items = [*prior_items, snapshot]
    bundle = export_bundle(
        updated_items,
        metadata={
            "source": "openminion-repo-sentinel",
            "latest_repo": report.repo_name,
            "snapshot_count": len(updated_items),
        },
    )
    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    save_bundle(bundle, bundle_path)
    receipt = import_bundle(bundle, trust_mode="direct")
    return bundle, receipt
