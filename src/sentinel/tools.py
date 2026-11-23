"""Custom @tool functions registered dynamically on OpenMinion Agent turns."""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

from openminion import tool

_SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
}

_SECRET_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("private_key_header", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("openai_like_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("github_pat", re.compile(r"\b(?:ghp|gho|ghu|ghs)_[A-Za-z0-9]{30,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("telegram_bot_token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")),
]


def _resolve_repo(repo_path: str) -> Path:
    root = Path(repo_path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError(f"Repository path does not exist or is not a directory: {root}")
    return root


@tool(
    name="inspect_git_repo",
    description="Inspect a local Git repository's branch, recent commits, dirty files, and build manifests.",
    idempotent=True,
    tags=("git", "release", "readonly"),
)
def inspect_git_repo(repo_path: str) -> str:
    """Return JSON metadata about repository history, manifests, and working-tree cleanliness."""
    root = _resolve_repo(repo_path)
    manifests = [
        name
        for name in ("package.json", "pyproject.toml", "go.mod", "gnomod.toml", "Cargo.toml", "Dockerfile")
        if (root / name).exists()
    ]

    git_info: dict[str, object] = {"is_git_repo": (root / ".git").exists()}
    if git_info["is_git_repo"]:
        def _git(*args: str) -> str:
            res = subprocess.run(
                ["git", "-C", str(root), *args],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            return res.stdout.strip()

        git_info["branch"] = _git("rev-parse", "--abbrev-ref", "HEAD")
        git_info["recent_commits"] = [
            line for line in _git("log", "--max-count=5", "--oneline").splitlines() if line
        ]
        dirty = [line for line in _git("status", "--porcelain").splitlines() if line]
        git_info["dirty_count"] = len(dirty)
        git_info["dirty_sample"] = dirty[:10]

    return json.dumps(
        {
            "repo_name": root.name,
            "path": str(root),
            "manifests": manifests,
            "git": git_info,
        },
        ensure_ascii=True,
    )


@tool(
    name="scan_secret_leaks",
    description="Scan repository text files for accidentally hardcoded private keys, API keys, or bot tokens.",
    idempotent=True,
    tags=("security", "readonly"),
)
def scan_secret_leaks(repo_path: str) -> str:
    """Walk text files up to 256 KB each and return structured secret pattern hits without leaking values."""
    root = _resolve_repo(repo_path)
    findings: list[dict[str, object]] = []
    files_scanned = 0

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            if fpath.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".wasm", ".ehpk", ".exe", ".zip", ".pdf"}:
                continue
            try:
                if fpath.stat().st_size > 262_144:
                    continue
                text = fpath.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            files_scanned += 1
            rel = str(fpath.relative_to(root)).replace("\\", "/")
            for lineno, line in enumerate(text.splitlines(), start=1):
                for rule_name, pattern in _SECRET_RULES:
                    if pattern.search(line):
                        findings.append({"file": rel, "line": lineno, "rule": rule_name})

    return json.dumps(
        {
            "repo_name": root.name,
            "files_scanned": files_scanned,
            "findings": findings,
            "clean": len(findings) == 0,
        },
        ensure_ascii=True,
    )


@tool(
    name="check_release_readiness",
    description="Verify whether a repository includes README, LICENSE, .gitignore, and automated tests.",
    idempotent=True,
    tags=("release", "qa", "readonly"),
)
def check_release_readiness(repo_path: str) -> str:
    """Check standard open-source release hygiene artifacts and report missing items."""
    root = _resolve_repo(repo_path)
    has_readme = any((root / p).exists() for p in ("README.md", "README.rst", "README.txt"))
    has_license = any((root / p).exists() for p in ("LICENSE", "LICENSE.md", "LICENSE.txt"))
    has_gitignore = (root / ".gitignore").exists()

    test_files: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fname in filenames:
            low = fname.lower()
            if (
                low.startswith("test_")
                or low.endswith("_test.py")
                or low.endswith("_test.go")
                or low.endswith("_test.gno")
                or ".test." in low
                or ".spec." in low
            ):
                test_files.append(str((Path(dirpath) / fname).relative_to(root)).replace("\\", "/"))

    gaps: list[str] = []
    if not has_readme:
        gaps.append("Missing README.md")
    if not has_license:
        gaps.append("Missing LICENSE")
    if not has_gitignore:
        gaps.append("Missing .gitignore")
    if not test_files:
        gaps.append("No automated test files detected")

    return json.dumps(
        {
            "repo_name": root.name,
            "has_readme": has_readme,
            "has_license": has_license,
            "has_gitignore": has_gitignore,
            "test_file_count": len(test_files),
            "test_files_sample": test_files[:8],
            "gaps": gaps,
        },
        ensure_ascii=True,
    )


@tool(
    name="write_triage_report",
    description="Write a Markdown release-triage report to disk (requires operator approval).",
    dangerous=True,
    idempotent=False,
    tags=("release", "write"),
)
def write_triage_report(output_path: str, markdown_body: str) -> str:
    """Persist a Markdown report file after OpenMinion action policy approval."""
    target = Path(output_path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(markdown_body, encoding="utf-8")
    return json.dumps({"written": True, "path": str(target), "bytes": len(markdown_body.encode("utf-8"))})
