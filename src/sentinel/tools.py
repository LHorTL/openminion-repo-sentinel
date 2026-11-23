"""Custom @tool functions registered dynamically on OpenMinion Agent, Handoff, and subagent turns."""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

from openminion import tool

_SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "target",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}

_BINARY_EXTS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".wasm",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".zip",
    ".tar",
    ".gz",
    ".pdf",
    ".pyc",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".whl",
}

_STANDARD_MANIFESTS = (
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "go.mod",
    "Cargo.toml",
    "Dockerfile",
    "Makefile",
    "pom.xml",
)

_SECRET_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("private_key_header", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("openai_like_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("github_pat", re.compile(r"\b(?:ghp|gho|ghu|ghs)_[A-Za-z0-9]{30,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("telegram_bot_token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")),
]

_ALLOWED_WRITE_ROOT: ContextVar[Path | None] = ContextVar(
    "sentinel_allowed_write_root", default=None
)


@contextmanager
def scoped_write_root(root: Path | str | None) -> Iterator[Path | None]:
    """Bind an active workspace containment root for dangerous report writes."""
    resolved = Path(root).expanduser().resolve() if root is not None else None
    token = _ALLOWED_WRITE_ROOT.set(resolved)
    try:
        yield resolved
    finally:
        _ALLOWED_WRITE_ROOT.reset(token)


def _resolve_repo(repo_path: str) -> Path:
    root = Path(repo_path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError(f"Repository path does not exist or is not a directory: {root}")
    return root


def _run_git(root: Path, *args: str) -> tuple[bool, str]:
    try:
        res = subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False, ""
    return res.returncode == 0, res.stdout.strip()


def _is_probably_binary(path: Path) -> bool:
    if path.suffix.lower() in _BINARY_EXTS:
        return True
    try:
        with path.open("rb") as handle:
            chunk = handle.read(4096)
    except OSError:
        return True
    return b"\x00" in chunk


def _redacted_hint(line: str, rel_path: str) -> str:
    stripped = line.strip()
    if stripped.startswith(("#", "//", "/*", "*")):
        return f"comment line in {rel_path}"
    if "=" in stripped or ":" in stripped:
        lhs = re.split(r"[=:]", stripped, maxsplit=1)[0].strip()
        lhs_clean = re.sub(r"[^A-Za-z0-9_.\"' -]", "", lhs)[:32]
        if lhs_clean:
            return f"assignment '{lhs_clean}' in {rel_path}"
    return f"literal match in {rel_path}"


@tool(
    name="inspect_git_repo",
    description="Inspect a local Git repository's branch, recent commits, dirty files, and build manifests.",
    min_scope="READ_ONLY",
    idempotent=True,
    tags=("git", "release", "readonly"),
)
def inspect_git_repo(repo_path: str) -> str:
    """Return JSON metadata about repository history, manifests, and working-tree cleanliness."""
    root = _resolve_repo(repo_path)
    manifests = [name for name in _STANDARD_MANIFESTS if (root / name).exists()]
    if (root / ".github" / "workflows").is_dir():
        manifests.append(".github/workflows")

    git_info: dict[str, object] = {"is_git_repo": (root / ".git").exists()}
    if git_info["is_git_repo"]:
        ok_branch, branch = _run_git(root, "rev-parse", "--abbrev-ref", "HEAD")
        _, log_out = _run_git(root, "log", "--max-count=5", "--oneline")
        _, status_out = _run_git(root, "status", "--porcelain")
        git_info["git_available"] = ok_branch
        git_info["branch"] = branch
        git_info["recent_commits"] = [line for line in log_out.splitlines() if line]
        dirty = [line for line in status_out.splitlines() if line]
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
    min_scope="READ_ONLY",
    idempotent=True,
    tags=("security", "readonly"),
)
def scan_secret_leaks(repo_path: str) -> str:
    """Walk text files up to 256 KB each and return structured secret pattern hits without leaking values."""
    root = _resolve_repo(repo_path)
    findings: list[dict[str, object]] = []
    files_scanned = 0

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        for fname in sorted(filenames):
            fpath = Path(dirpath) / fname
            try:
                if fpath.stat().st_size > 262_144:
                    continue
                if _is_probably_binary(fpath):
                    continue
                text = fpath.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            files_scanned += 1
            rel = str(fpath.relative_to(root)).replace("\\", "/")
            for lineno, line in enumerate(text.splitlines(), start=1):
                for rule_name, pattern in _SECRET_RULES:
                    if pattern.search(line):
                        findings.append(
                            {
                                "file": rel,
                                "line": lineno,
                                "rule": rule_name,
                                "context_hint": _redacted_hint(line, rel),
                            }
                        )

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
    min_scope="READ_ONLY",
    idempotent=True,
    tags=("release", "qa", "readonly"),
)
def check_release_readiness(repo_path: str) -> str:
    """Check standard open-source release hygiene artifacts and report missing items."""
    root = _resolve_repo(repo_path)
    has_readme = any((root / p).exists() for p in ("README.md", "README.rst", "README.txt"))
    has_license = any((root / p).exists() for p in ("LICENSE", "LICENSE.md", "LICENSE.txt"))
    has_gitignore = (root / ".gitignore").exists()
    has_ci = (root / ".github" / "workflows").is_dir()

    test_files: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        for fname in sorted(filenames):
            low = fname.lower()
            if (
                low.startswith("test_")
                or low.endswith("_test.py")
                or low.endswith("_test.go")
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
            "has_ci_workflows": has_ci,
            "test_file_count": len(test_files),
            "test_files_sample": test_files[:8],
            "gaps": gaps,
        },
        ensure_ascii=True,
    )


@tool(
    name="audit_dependency_and_secret_context",
    description="Deep security specialist audit for committed .env/key files, unpinned dependencies, and supply-chain risks.",
    min_scope="READ_ONLY",
    idempotent=True,
    tags=("security", "specialist", "readonly"),
)
def audit_dependency_and_secret_context(repo_path: str) -> str:
    """Dedicated read-only tool owned exclusively by the security_specialist Handoff peer."""
    root = _resolve_repo(repo_path)
    committed_env_files: list[str] = []
    dependency_risks: list[dict[str, str]] = []
    files_reviewed = 0

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        for fname in sorted(filenames):
            fpath = Path(dirpath) / fname
            rel = str(fpath.relative_to(root)).replace("\\", "/")
            low = fname.lower()
            files_reviewed += 1
            if (low == ".env" or low.startswith(".env.")) and not low.endswith((".example", ".sample", ".template")):
                committed_env_files.append(rel)
            if low.endswith((".pem", ".key", ".p12", ".pfx")) and "example" not in low:
                dependency_risks.append(
                    {
                        "manifest": rel,
                        "issue": f"Private key or certificate artifact present in repository tree ({fname})",
                        "severity": "HIGH",
                    }
                )

    pkg_json = root / "package.json"
    if pkg_json.is_file():
        try:
            pkg = json.loads(pkg_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pkg = {}
        deps = {}
        for section in ("dependencies", "devDependencies"):
            if isinstance(pkg.get(section), dict):
                deps.update(pkg[section])
        wildcards = [name for name, ver in deps.items() if str(ver).strip() in {"*", "latest"}]
        if wildcards:
            dependency_risks.append(
                {
                    "manifest": "package.json",
                    "issue": f"Unpinned wildcard/latest npm dependencies: {', '.join(sorted(wildcards)[:5])}",
                    "severity": "MEDIUM",
                }
            )

    req_txt = root / "requirements.txt"
    if req_txt.is_file():
        try:
            lines = [
                ln.strip()
                for ln in req_txt.read_text(encoding="utf-8", errors="ignore").splitlines()
                if ln.strip() and not ln.strip().startswith("#")
            ]
        except OSError:
            lines = []
        unpinned = [ln for ln in lines if not re.search(r"(==|>=|<=|~=|!=|<|>)", ln)]
        if unpinned:
            dependency_risks.append(
                {
                    "manifest": "requirements.txt",
                    "issue": f"Unpinned Python dependencies in requirements.txt ({len(unpinned)} entries)",
                    "severity": "MEDIUM",
                }
            )

    dockerfile = root / "Dockerfile"
    if dockerfile.is_file():
        try:
            df_text = dockerfile.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            df_text = ""
        if re.search(r"^\s*FROM\s+\S+:latest\b", df_text, re.MULTILINE):
            dependency_risks.append(
                {
                    "manifest": "Dockerfile",
                    "issue": "Base image uses mutable ':latest' tag instead of pinned version/digest",
                    "severity": "LOW",
                }
            )

    verdict = "CLEAR"
    if committed_env_files or any(r["severity"] == "HIGH" for r in dependency_risks):
        verdict = "BLOCK_RELEASE"
    elif dependency_risks:
        verdict = "REVIEW_REQUIRED"

    return json.dumps(
        {
            "repo_name": root.name,
            "files_reviewed": files_reviewed,
            "committed_env_files": committed_env_files,
            "dependency_risks": dependency_risks,
            "verdict": verdict,
        },
        ensure_ascii=True,
    )


@tool(
    name="summarize_recent_changes",
    description="Collect top-level structure and recent commit subjects to draft an executive release brief.",
    min_scope="READ_ONLY",
    idempotent=True,
    tags=("release", "subagent", "readonly"),
)
def summarize_recent_changes(repo_path: str) -> str:
    """Dedicated read-only tool owned exclusively by the bounded release_brief_writer subagent."""
    root = _resolve_repo(repo_path)
    top_entries = sorted(
        p.name for p in root.iterdir() if p.name not in _SKIP_DIRS
    )[:15]
    commits: list[str] = []
    if (root / ".git").exists():
        _, log_out = _run_git(root, "log", "--max-count=8", "--pretty=format:%h %s")
        commits = [ln for ln in log_out.splitlines() if ln]

    return json.dumps(
        {
            "repo_name": root.name,
            "top_level_entries": top_entries,
            "recent_commits": commits,
            "recent_commit_count": len(commits),
        },
        ensure_ascii=True,
    )


@tool(
    name="write_triage_report",
    description="Write a Markdown release-triage report inside the allowed workspace root (requires operator approval).",
    dangerous=True,
    idempotent=False,
    tags=("release", "write"),
)
def write_triage_report(
    output_path: str,
    markdown_body: str,
) -> str:
    """Persist a Markdown report file after OpenMinion action policy approval and strict workspace containment.

    Containment root is controlled solely by the trusted host via `scoped_write_root(...)`
    (failing closed to `Path.cwd().resolve()` when unset) — never exposed as an LLM-controllable
    tool argument.
    """
    raw_target = Path(output_path).expanduser()
    allowed_root = _ALLOWED_WRITE_ROOT.get() or Path.cwd().resolve()
    candidate = (allowed_root / raw_target) if not raw_target.is_absolute() else raw_target
    target = candidate.resolve()
    if not target.is_relative_to(allowed_root):
        raise ValueError(
            f"Refusing to write outside allowed workspace root ({allowed_root}): {target}"
        )

    if ".git" in target.parts:
        raise ValueError(f"Refusing to write inside .git metadata directory: {target}")

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(markdown_body, encoding="utf-8")
    return json.dumps(
        {
            "written": True,
            "path": str(target),
            "bytes": len(markdown_body.encode("utf-8")),
        },
        ensure_ascii=True,
    )
