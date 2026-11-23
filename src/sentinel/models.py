"""Typed Pydantic output models enforced by OpenMinion Agent(..., output_type=...)."""

from __future__ import annotations

from typing import Literal
from pydantic import BaseModel, Field


class SecretFinding(BaseModel):
    """A single suspicious secret pattern match found during repository triage."""

    file: str = Field(..., description="Repository-relative file path")
    line: int = Field(..., ge=1, description="1-based line number")
    rule: str = Field(..., description="Triggered secret rule identifier")


class ReleaseTriageReport(BaseModel):
    """Structured final triage verdict emitted by the OpenMinion Sentinel agent."""

    repo_name: str = Field(..., description="Repository directory name")
    release_ready: bool = Field(..., description="True only when zero secret leaks and core docs/tests exist")
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = Field(
        ..., description="Overall release risk level"
    )
    secret_findings: list[SecretFinding] = Field(
        default_factory=list, description="Detected hardcoded secret patterns"
    )
    checklist_gaps: list[str] = Field(
        default_factory=list, description="Missing release artifacts (README, LICENSE, tests, .gitignore)"
    )
    recommended_actions: list[str] = Field(
        default_factory=list, description="Concrete next steps before tagging a release"
    )
    summary: str = Field(..., description="Concise one-paragraph executive verdict")
