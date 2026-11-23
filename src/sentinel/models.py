"""Typed Pydantic output models enforced by OpenMinion Agent(..., output_type=...)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class SecretFinding(BaseModel):
    """A single suspicious secret pattern match found during repository triage."""

    file: str = Field(..., description="Repository-relative file path")
    line: int = Field(..., ge=1, description="1-based line number")
    rule: str = Field(..., description="Triggered secret rule identifier")
    context_hint: str = Field(
        default="",
        description="Safe redacted location hint without exposing secret material",
    )


class DependencyRisk(BaseModel):
    """A manifest or repository security hygiene issue found by the security specialist."""

    manifest: str = Field(..., description="Manifest or repository file path")
    issue: str = Field(..., description="Description of the security or dependency risk")
    severity: Literal["LOW", "MEDIUM", "HIGH"] = Field(
        ..., description="Risk severity level"
    )


class SecurityAuditVerdict(BaseModel):
    """Typed verdict returned by the delegated security_specialist Handoff peer."""

    specialist_name: str = Field(
        default="security_specialist",
        description="Specialist agent identifier",
    )
    files_reviewed: int = Field(default=0, ge=0, description="Files inspected by specialist")
    committed_env_files: list[str] = Field(
        default_factory=list,
        description="Committed .env or credential files detected in repository tree",
    )
    dependency_risks: list[DependencyRisk] = Field(
        default_factory=list,
        description="Dependency and supply-chain hygiene issues detected",
    )
    verdict: Literal["CLEAR", "REVIEW_REQUIRED", "BLOCK_RELEASE"] = Field(
        ..., description="Specialist security gate decision"
    )
    notes: str = Field(..., description="Concise specialist rationale")


class ReleaseBrief(BaseModel):
    """Typed executive summary synthesized by the bounded release_brief_writer subagent."""

    repo_name: str = Field(..., description="Repository directory name")
    recent_commit_count: int = Field(default=0, ge=0, description="Recent commits inspected")
    change_highlights: list[str] = Field(
        default_factory=list,
        description="Key changes or repository highlights for release notes",
    )
    release_recommendation: str = Field(
        ..., description="Actionable one-sentence release recommendation"
    )


class TriageDiffSummary(BaseModel):
    """Cross-run comparison computed from persisted OpenMinion MemoryBundle history."""

    has_previous_run: bool = Field(
        default=False,
        description="True when a prior triage snapshot existed in the MemoryBundle",
    )
    previous_run_id: str | None = Field(
        default=None, description="Run ID of the previous baseline snapshot"
    )
    previous_timestamp: str | None = Field(
        default=None, description="UTC ISO-8601 timestamp of the prior snapshot"
    )
    new_secrets: list[str] = Field(
        default_factory=list, description="Secret findings introduced since prior run"
    )
    resolved_secrets: list[str] = Field(
        default_factory=list, description="Secret findings fixed since prior run"
    )
    new_gaps: list[str] = Field(
        default_factory=list, description="Checklist gaps introduced since prior run"
    )
    resolved_gaps: list[str] = Field(
        default_factory=list, description="Checklist gaps fixed since prior run"
    )
    trend: Literal["baseline", "improved", "regressed", "unchanged"] = Field(
        default="baseline",
        description="Overall security/readiness trajectory vs prior run",
    )


class ReleaseTriageReport(BaseModel):
    """Structured final triage verdict emitted by the OpenMinion Sentinel agent."""

    repo_name: str = Field(..., description="Repository directory name")
    release_ready: bool = Field(
        ..., description="True only when zero secret leaks, no blocking specialist verdict, and core docs/tests exist"
    )
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = Field(
        ..., description="Overall release risk level"
    )
    secret_findings: list[SecretFinding] = Field(
        default_factory=list, description="Detected hardcoded secret patterns"
    )
    checklist_gaps: list[str] = Field(
        default_factory=list,
        description="Missing release artifacts (README, LICENSE, tests, .gitignore)",
    )
    dependency_risks: list[DependencyRisk] = Field(
        default_factory=list,
        description="Dependency and hygiene findings contributed by security_specialist",
    )
    security_specialist_verdict: str | None = Field(
        default=None,
        description="Verdict returned via OpenMinion Handoff to security_specialist",
    )
    recommended_actions: list[str] = Field(
        default_factory=list, description="Concrete next steps before tagging a release"
    )
    summary: str = Field(..., description="Concise one-paragraph executive verdict")
    diff_from_previous: TriageDiffSummary | None = Field(
        default=None,
        description="Cross-run delta derived from persisted OpenMinion MemoryBundle",
    )
    release_brief: ReleaseBrief | None = Field(
        default=None,
        description="Executive release brief produced by the bounded subagent",
    )
