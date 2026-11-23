# RepoTriageSentinel (`openminion` 0.1.24)

**Automated Git Release-Readiness & Secret-Leak Triage Agent** built for **Cortensor Hackathon #5** using the **OpenMinion 0.1 Python SDK (`openminion==0.1.24`)**.

---

## What It Does

`RepoTriageSentinel` executes a repeatable pre-release audit workflow over any local repository using OpenMinion's core runtime primitives:

1. **Custom `@tool` Suite (`src/sentinel/tools.py`)**:
   - `inspect_git_repo` (`idempotent=True`): Reads branch, recent commits, working-tree cleanliness, and build manifests (`package.json`, `pyproject.toml`, `go.mod`, `gnomod.toml`, `Cargo.toml`, `Dockerfile`).
   - `scan_secret_leaks` (`idempotent=True`): Scans source files for accidentally hardcoded private keys, AWS keys, GitHub PATs, OpenAI keys, and Telegram bot tokens without leaking values.
   - `check_release_readiness` (`idempotent=True`): Verifies `README`, `LICENSE`, `.gitignore`, and automated test coverage.
   - `write_triage_report` (`dangerous=True`): Writes a Markdown triage artifact to disk under OpenMinion's `action_policy` + `approval_callback` gate.
2. **Typed Pydantic `output_type` (`src/sentinel/models.py`)**:
   - Enforces `ReleaseTriageReport` (`release_ready`, `risk_level`, `secret_findings`, `checklist_gaps`, `recommended_actions`, `summary`) via `Agent[str, ReleaseTriageReport]`.
3. **Specialist `Handoff` Delegation & Runtime Diagnostics (`src/sentinel/agent.py`)**:
   - Registers a `security_specialist` peer via `openminion.Handoff`.
   - Captures `APIRuntime.runtime_posture()`, `tool_inventory_report(readiness=True)`, and `openminion doctor --json`.
4. **Native Cortensor & OpenAI-Compatible Support + Reproducible Offline E2E Mode**:
   - Supports `--provider cortensor` (using `CORTENSOR_API_KEY` + Cortensor Portal / Router `base_url`), `--provider openai`, `--provider ollama`, or `--demo-local` (runs the full OpenMinion HTTP tool-calling pipeline against a local OpenAI-compatible server with zero API keys).

## OpenMinion 0.1.24 Developer Feedback & Bug Report

See **[SDK_FEEDBACK_REPORT.md](./SDK_FEEDBACK_REPORT.md)** for 7 empirically reproduced SDK findings (config format asymmetry, broken wheel-relative doc link, `config init` vs `doctor --json` identity mismatch, invalid default Anthropic model ID, programmatic config ergonomic gap, `@tool` read-only / `approval_callback` + `output_type` collision, and multi-call orchestration latency).

## Quick Start

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate  |  macOS/Linux: source .venv/bin/activate
pip install -e .

# Run end-to-end tests (exercises APIRuntime, Agent, @tool, Handoff, approval_callback, doctor)
python -m unittest discover -s tests -v

# Run an offline reproducible triage demo against this repo
repo-sentinel . --demo-local --report-out ./triage-demo.md --auto-approve

# Run against live Cortensor Portal / Router (set CORTENSOR_API_KEY in env)
repo-sentinel . --provider cortensor --base-url https://your-cortensor-router/api/v2/completions
```

## License

MIT — see [LICENSE](./LICENSE).
