# OpenMinion 0.1.24 Upstream Fix PRs & RepoTriageSentinel v2.0.0

**3 Source-Accepted Upstream Fix PRs on [`OpenMinion/openminion`](https://github.com/OpenMinion/openminion) (`#862`, `#863`, `#864` — `Source accepted` by `@wireindevice`, `18/18` CI GREEN) + a Multi-Agent Git Release-Readiness, Secret-Leak & Cross-Run Regression Triage Harness (`openminion==0.1.24`)** built for **Cortensor Hackathon #5**.

> **Execution Transparency**: **OpenMinion 0.1.24 runtime-backed; offline deterministic demo harness.** Live Cortensor Portal (`https://api.cortensor.app/v1`, `oss-20b`) and direct Cortensor Router integration are supported via `CORTENSOR_API_KEY`, while the bundled demo walkthrough and `11/11` automated test suite run against the local deterministic OpenAI-compatible harness (`--demo-local`) with zero external API keys required.

- **Technical Showcase (GitHub Pages)**: [https://lhortl.github.io/openminion-repo-sentinel/](https://lhortl.github.io/openminion-repo-sentinel/)
- **HD Walkthrough Demo Video (`v2.0.0`, 1280×720 H.264, Offline Deterministic Demo Harness)**: [Download / Watch `repotriagesentinel-v2-demo.mp4`](https://github.com/LHorTL/openminion-repo-sentinel/releases/download/v2.0.0/repotriagesentinel-v2-demo.mp4) ([GitHub Release `v2.0.0`](https://github.com/LHorTL/openminion-repo-sentinel/releases/tag/v2.0.0))
- **Full Developer Field Report & Verified Patch Archive**: [SDK_FEEDBACK_REPORT.md](./SDK_FEEDBACK_REPORT.md) · [patches/README.md](./patches/README.md)

---

## 1. Upstream Fix PRs on `OpenMinion/openminion` (`3/3 Source Accepted`, `18/18` CI Green) & SDK Audit

While building and stress-testing against unmodified `openminion==0.1.24`, we isolated **7 source-verified SDK bugs**, authored **5 `git apply`-verified unified patches**, and submitted **3 upstream Fix PRs** to [`OpenMinion/openminion`](https://github.com/OpenMinion/openminion) (`dev`, forked at [`LHorTL/openminion`](https://github.com/LHorTL/openminion)):

| Upstream PR / Patch | Severity | Review & CI Status | Upstream Tests | Target Module & Root-Cause Fix |
| :--- | :--- | :--- | :--- | :--- |
| [**PR #862**](https://github.com/openminion/openminion/pull/862) · [`Patch 0001`](./patches/0001-cortensor-enable-fallback-tool-calls-and-http-reuse.patch) | **S-Tier / Cortensor** | **`Source accepted`** (`@wireindevice`) · **`18/18` CI GREEN** | `169 passed` | `cortensor/adapter.py`: replaces hardcoded `fallback_enabled=False` (`:470`) with `supports_fallback_tool_calling()` so `/api/v2/completions` tool calls parse instead of silently dropping; restores `http_client` connection reuse (`:261-279`). |
| [**PR #863**](https://github.com/openminion/openminion/pull/863) · [`Patch 0003`](./patches/0003-policy-windows-skip-posix-world-writable-check.patch) | **A-Tier / Windows** | **`Source accepted`** (`@wireindevice`) · **`18/18` CI GREEN** | `48 passed` | `policy/diagnostics/security.py`: skips POSIX `stat.S_IWOTH` checks on Windows (`os.name == "nt"`), eliminating 3 false-positive `Path is world-writable (0o666/0o777)` / `chmod` warnings in `openminion doctor`. |
| [**PR #864**](https://github.com/openminion/openminion/pull/864) · [`Patch 0004`](./patches/0004-config-default-channel-and-wheel-doc-url.patch) | **A-Tier / Config DX** | **`Source accepted`** (`@wireindevice`) · **`18/18` CI GREEN** | `85 passed` | `base/config/core.py`: defaults `AgentProfileConfig.default_channel` to `"console"`, fixing turn-1 `RuntimeError: inbound authenticity denied (reason=invalid_channel)` under programmatic `APIRuntime.from_config()`. |
| [`Patch 0002`](./patches/0002-handoff-shared-tool-reuse-and-callback-forwarding.patch) | **S-Tier / SDK Core** | Patch archive (`git apply --check` OK) | Repro in suite | `api/agent.py`, `api/handoff.py`: fails fast on shared-runtime `Handoff` temporary `@tool` deadlocks, prevents same-thread `@tool` collisions, and forwards `approval_callback`/`timeout_seconds`/`cancel_event`/`on_delta`. |
| [`Patch 0005`](./patches/0005-agent-typed-approval-error-before-output-coercion.patch) | **A-Tier / Typed API** | Patch archive (`git apply --check` OK) | Repro in suite | `api/agent.py`: raises typed `AgentApprovalRequiredError` before `_coerce_output()` whenever a structured-output turn pauses on policy confirmation or denial. |

See **[SDK_FEEDBACK_REPORT.md](./SDK_FEEDBACK_REPORT.md)** for full line-by-line root-cause analyses, standalone bug reproducers (all automated in [`tests/test_sentinel.py`](./tests/test_sentinel.py)), and Cortensor latency findings (`7` sequential LLM calls per single-tool turn; `26` calls across a 3-agent turn).

---

## 2. RepoTriageSentinel v2.0.0 — Runtime Architecture & Offline Deterministic Demo Harness

`RepoTriageSentinel` runs a repeatable pre-release security & hygiene audit workflow over any local repository, exercising OpenMinion `0.1.24`'s native runtime primitives end-to-end (**OpenMinion 0.1.24 runtime-backed; offline deterministic demo harness**, with optional BYOK live provider support):

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

### Key Capabilities
1. **Least-Privilege `@tool` Suite (`src/sentinel/tools.py`)**:
   - Five `min_scope="READ_ONLY", idempotent=True` tools that execute with **zero** confirmation prompts under `action_policy.mode="ask"`.
   - One `dangerous=True, idempotent=False` report writer (`write_triage_report`) gated by OpenMinion's `approval_callback` AND hardened with strict `scoped_write_root()` path-traversal containment (rejecting `..` escapes and `.git/` writes).
2. **Peer `Handoff` Specialist Delegation (`src/sentinel/agent.py`)**:
   - Delegates deep dependency, `.env`, key-file, and Dockerfile `:latest` inspection to `security_specialist` (`Agent[str, SecurityAuditVerdict]`) running on its own isolated `APIRuntime` (avoiding OpenMinion 0.1.24's cross-thread `temporary_registration_scope` deadlock).
3. **Bounded `subagent()` Execution (`src/sentinel/agent.py`)**:
   - Spawns `release_brief_writer` via `openminion.subagent(...)` with an isolated `SubagentRunContext` to produce a typed `ReleaseBrief`.
4. **Streaming `run_stream(on_delta=...)` Progress Events**:
   - Streams `PhaseStatus`, `budget_event`, `tool_started`, and `tool_completed` deltas (`--stream` prints live runtime progress to `stderr`).
5. **Cross-Run `MemoryBundle` Persistence & Regression Diffing (`src/sentinel/memory_store.py`)**:
   - Persists `triage_memory_bundle.json` inside `--state-dir` via `export_bundle` / `save_bundle` and imports prior snapshots via `load_bundle` / `import_bundle` to compute `new_secrets`, `resolved_secrets`, `new_gaps`, `resolved_gaps`, and `trend` (`baseline` / `improved` / `regressed` / `unchanged`).
6. **Offline Deterministic Harness + BYOK Cortensor & Multi-Provider Presets**:
   - Bundled `--demo-local` starts an in-process OpenAI-compatible deterministic harness (`src/sentinel/mock_openai.py`) so every judge and CI run can reproduce the full multi-agent workflow offline with zero API keys.
   - Live endpoint presets are wired and ready via environment variables: `--provider cortensor-portal` (`https://api.cortensor.app/v1`, `oss-20b`, `480s` timeout, `CORTENSOR_API_KEY`), `--provider cortensor` (direct router, `420s`), `--provider openai`, `--provider openrouter`, `--provider ollama`, and `--provider anthropic`.

---

## 3. Quick Start & Verification

```bash
python -m venv .venv
# Windows PowerShell: .\.venv\Scripts\Activate.ps1
# macOS / Linux:      source .venv/bin/activate
pip install -e .
```

### 1. Run Full End-to-End & SDK-Bug Reproducer Suite (`11/11` Tests)

All 11 tests run against the native OpenMinion `0.1.24` runtime using the offline deterministic OpenAI-compatible harness:

```powershell
# Windows PowerShell
$env:PYTHONPATH = "src"
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

```bash
# macOS / Linux
PYTHONPATH=src python -m unittest discover -s tests -v
```

### 2. Run the Offline Deterministic Demo Harness (Cross-Run Diffing + Streaming)

This is the exact reproducible mode captured in [`repotriagesentinel-v2-demo.mp4`](https://github.com/LHorTL/openminion-repo-sentinel/releases/download/v2.0.0/repotriagesentinel-v2-demo.mp4) (zero external API keys required):

```powershell
# Run 1 (creates baseline MemoryBundle in .\.sentinel-state\triage_memory_bundle.json)
repo-sentinel . --demo-local --state-dir .\.sentinel-state --report-out .\triage-demo.md --auto-approve --stream

# Run 2 (imports MemoryBundle & reports cross-run diff_from_previous)
repo-sentinel . --demo-local --state-dir .\.sentinel-state --stream
```

### 3. Optional: Connect a Live Cortensor Portal or BYOK Endpoint (`CORTENSOR_API_KEY`)

Live inference integration is supported when you supply your own provider key in the environment (never commit or hardcode keys):

```powershell
# Cortensor Portal (OpenAI-compatible endpoint, oss-20b)
$env:CORTENSOR_API_KEY = "<your-cortensor-portal-api-key>"
repo-sentinel . --provider cortensor-portal --model oss-20b --state-dir .\.sentinel-state --report-out .\triage-report.md --auto-approve --stream

# OpenAI
$env:OPENAI_API_KEY = "<your-openai-key>"
repo-sentinel . --provider openai --model gpt-4.1-mini --state-dir .\.sentinel-state --stream

# Local Ollama (no external API key required)
repo-sentinel . --provider ollama --model llama3.1 --state-dir .\.sentinel-state --stream
```

---

## Reproducible Walkthrough Checklist (Offline Deterministic Demo Harness)

1. Run `repo-sentinel <target-repo> --demo-local --state-dir ./.demo-state --stream` (or supply `--provider cortensor-portal` with `CORTENSOR_API_KEY`) against a repo containing a synthetic test secret + `Dockerfile` `:latest` to observe `run_stream()` tool calls (`inspect_git_repo`, `scan_secret_leaks`, `check_release_readiness`, `transfer_to_security_specialist`), `CRITICAL` verdict, and `triage_memory_bundle.json` creation.
2. Remove the synthetic secret and re-run with `--demo-local --state-dir ./.demo-state --report-out ./triage.md --auto-approve --stream` to verify `MemoryBundle` cross-run `resolved_secrets`, `trend: "improved"`, and approval-gated report creation.
3. Run `unittest discover -s tests -v` to confirm all **11/11** automated E2E & SDK-bug reproducer tests pass.

## License

MIT — see [LICENSE](./LICENSE).
