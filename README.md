# RepoTriageSentinel v2.0.0 (`openminion==0.1.24`)

**Multi-Agent Git Release-Readiness, Secret-Leak & Cross-Run Regression Triage Agent** built for **Cortensor Hackathon #5** using the **OpenMinion 0.1 Python SDK (`openminion==0.1.24`)**.

- **HD Walkthrough Demo Video (`v2.0.0`, 1280×720 H.264)**: [Download / Watch `repotriagesentinel-v2-demo.mp4`](https://github.com/LHorTL/openminion-repo-sentinel/releases/download/v2.0.0/repotriagesentinel-v2-demo.mp4) ([GitHub Release `v2.0.0`](https://github.com/LHorTL/openminion-repo-sentinel/releases/tag/v2.0.0))
- **Live Upstream Fix PRs on [`OpenMinion/openminion`](https://github.com/OpenMinion/openminion)** (forked at [`LHorTL/openminion`](https://github.com/LHorTL/openminion) & starred):
  - [**PR #862**](https://github.com/openminion/openminion/pull/862) (`S-Tier / Cortensor`): `fix(llm): honor tool_call_strategy fallback parsing and http_client reuse in CortensorProvider` (`169 passed`)
  - [**PR #863**](https://github.com/openminion/openminion/pull/863) (`A-Tier / Windows`): `fix(policy): skip POSIX S_IWOTH world-writable check on Windows` (`48 passed`)
  - [**PR #864**](https://github.com/openminion/openminion/pull/864) (`A-Tier / Config DX`): `fix(config): default AgentProfileConfig.default_channel to console` (`85 passed`)

---

## Architecture & OpenMinion 0.1.24 Building Blocks Exercised

`RepoTriageSentinel` runs a repeatable pre-release security & hygiene audit workflow over any local repository, exercising OpenMinion's real runtime primitives end-to-end:

```text
CLI / run_repo_triage()
  ├── Programmatic OpenMinionConfig.from_dict() + APIRuntime.from_config()  (no config init shell-out)
  ├── MemoryBundle load_bundle() + import_bundle()  (loads prior triage baseline from --state-dir)
  ├── Agent[str, ReleaseTriageReport].run_stream(on_delta=...)
  │     ├── @tool(min_scope="READ_ONLY", idempotent=True): inspect_git_repo          [0 approval prompts]
  │     ├── @tool(min_scope="READ_ONLY", idempotent=True): scan_secret_leaks         [0 approval prompts]
  │     ├── @tool(min_scope="READ_ONLY", idempotent=True): check_release_readiness   [0 approval prompts]
  │     ├── Handoff -> transfer_to_security_specialist (dedicated peer APIRuntime)
  │     │     └── Agent[str, SecurityAuditVerdict] + @tool(min_scope="READ_ONLY"):
  │     │           audit_dependency_and_secret_context (.env, keys, unpinned deps, Dockerfile :latest)
  │     └── @tool(dangerous=True, idempotent=False): write_triage_report
  │           └── Policy-gated by approval_callback + strict workspace path-containment guard
  ├── subagent(sentinel_agent, name="release_brief_writer", output_type=ReleaseBrief)
  │     └── Isolated SubagentRunContext + @tool(min_scope="READ_ONLY"): summarize_recent_changes
  └── MemoryBundle export_bundle() + save_bundle()  (persists snapshot & computes cross-run diff trend)
```

### Key Features
1. **Least-Privilege `@tool` Suite (`src/sentinel/tools.py`)**:
   - Five `min_scope="READ_ONLY", idempotent=True` tools that execute with **zero** confirmation prompts under `action_policy.mode="ask"`.
   - One `dangerous=True, idempotent=False` report writer (`write_triage_report`) gated by OpenMinion's `approval_callback` AND hardened with strict `scoped_write_root()` path-traversal containment (rejecting `..` escapes and `.git/` writes).
2. **Real `Handoff` Specialist Delegation (`src/sentinel/agent.py`)**:
   - Delegates deep dependency, `.env`, key-file, and Dockerfile `:latest` inspection to `security_specialist` (`Agent[str, SecurityAuditVerdict]`) running on its own isolated `APIRuntime` (avoiding OpenMinion 0.1.24's cross-thread `temporary_registration_scope` deadlock).
3. **Real Bounded `subagent()` Execution (`src/sentinel/agent.py`)**:
   - Spawns `release_brief_writer` via `openminion.subagent(...)` with an isolated `SubagentRunContext` to produce a typed `ReleaseBrief`.
4. **Live `run_stream(on_delta=...)` Progress Streaming**:
   - Streams `PhaseStatus`, `budget_event`, `tool_started`, and `tool_completed` deltas (`--stream` prints live progress to `stderr`).
5. **Cross-Run `MemoryBundle` Persistence & Regression Diffing (`src/sentinel/memory_store.py`)**:
   - Persists `triage_memory_bundle.json` inside `--state-dir` via `export_bundle` / `save_bundle` and imports prior snapshots via `load_bundle` / `import_bundle` to compute `new_secrets`, `resolved_secrets`, `new_gaps`, `resolved_gaps`, and `trend` (`baseline` / `improved` / `regressed` / `unchanged`).
6. **Cortensor Portal & Multi-Provider Support + Offline E2E Harness**:
   - Built-in `--provider cortensor-portal` preset (`https://api.cortensor.app/v1`, `oss-20b`, `480s` timeout, `CORTENSOR_API_KEY`), `--provider cortensor` (direct router, `420s`), `--provider openai`, `--provider openrouter`, `--provider ollama`, `--provider anthropic`, plus `--demo-local` (schema-compliant local OpenAI-compatible server for deterministic offline CI).

---

## OpenMinion 0.1.24 Source-Verified Bug Report & Live Upstream Fix PRs

See **[SDK_FEEDBACK_REPORT.md](./SDK_FEEDBACK_REPORT.md)** and **[patches/README.md](./patches/README.md)** for **7 source-verified findings**, **5 `git apply`-verified unified patches**, and **3 live upstream Fix PRs** submitted to `OpenMinion/openminion` (`dev`):
- **S-Tier Cortensor Bug ([Upstream PR #862](https://github.com/openminion/openminion/pull/862))**: `CortensorProvider` hardcodes `fallback_enabled=False` (`cortensor/adapter.py:470`), silently dropping all `/api/v2/completions` fallback tool calls + missing `http_client` reuse (`:261-279`).
- **S-Tier Handoff Bug (Patch `0002`)**: Shared-runtime `Handoff` silent construction / swallowed `EXEC_ERROR`, same-thread shared-`@tool` crash, and dropped `approval_callback`/`timeout_seconds`/`cancel_event`/`on_delta`.
- **A-Tier Typed Output Bug (Patch `0005`)**: `Agent._run_once()` runs `_coerce_output()` on plain-text policy denial/confirmation prompts instead of raising a typed approval error.
- **A-Tier Programmatic Config Bug ([Upstream PR #864](https://github.com/openminion/openminion/pull/864))**: `AgentProfileConfig.default_channel=""` crashes `APIRuntime.from_config(...)` on turn 1 (`inbound authenticity denied`).
- **A-Tier Windows Bug ([Upstream PR #863](https://github.com/openminion/openminion/pull/863))**: `openminion doctor` emits 3 false-positive `Path is world-writable (0o666/0o777)` / `chmod` warnings on Windows.

---

## Quick Start

```bash
python -m venv .venv
# Windows PowerShell: .\.venv\Scripts\Activate.ps1
# macOS / Linux:      source .venv/bin/activate
pip install -e .
```

### 1. Run Full End-to-End Test Suite (11 Tests)

```powershell
# Windows PowerShell
$env:PYTHONPATH = "src"
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

```bash
# macOS / Linux
PYTHONPATH=src python -m unittest discover -s tests -v
```

### 2. Run Against Live Cortensor Portal (Real Model-Backed Run)

Set your key in the environment (never commit or hardcode keys):

```powershell
# Windows PowerShell
$env:CORTENSOR_API_KEY = "<your-cortensor-portal-api-key>"
repo-sentinel . --provider cortensor-portal --model oss-20b --state-dir .\.sentinel-state --report-out .\triage-report.md --auto-approve --stream
```

Or use any OpenAI-compatible / OpenRouter / local Ollama backend:

```powershell
# OpenAI
$env:OPENAI_API_KEY = "<your-openai-key>"
repo-sentinel . --provider openai --model gpt-4.1-mini --state-dir .\.sentinel-state --stream

# Local Ollama (no external API key required)
repo-sentinel . --provider ollama --model llama3.1 --state-dir .\.sentinel-state --stream
```

### 3. Run Reproducible Offline E2E Demo (Cross-Run Diffing + Streaming)

```powershell
# Run 1 (creates baseline MemoryBundle in .\.sentinel-state\triage_memory_bundle.json)
repo-sentinel . --demo-local --state-dir .\.sentinel-state --report-out .\triage-demo.md --auto-approve --stream

# Run 2 (imports MemoryBundle & reports cross-run diff_from_previous)
repo-sentinel . --demo-local --state-dir .\.sentinel-state --stream
```

---

## Demo Recording Checklist (1–5 Minute Real Model-Backed Video)

1. Run `repo-sentinel <target-repo> --provider cortensor-portal --state-dir ./.demo-state --stream` against a repo with a synthetic test secret + `Dockerfile` `:latest` to show live streaming tool calls (`inspect_git_repo`, `scan_secret_leaks`, `check_release_readiness`, `transfer_to_security_specialist`), `CRITICAL` verdict, and `triage_memory_bundle.json` creation.
2. Remove the synthetic secret and re-run with `--state-dir ./.demo-state --report-out ./triage.md --auto-approve --stream` to show `MemoryBundle` cross-run `resolved_secrets` + `trend: "improved"` and approval-gated report creation.
3. Run `unittest discover -s tests -v` to show all 11 automated E2E & SDK-bug reproducer tests passing.

## License

MIT — see [LICENSE](./LICENSE).
