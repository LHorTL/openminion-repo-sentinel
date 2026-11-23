# OpenMinion 0.1.24 Developer Field Report (Windows 11 + Python 3.13)

Submitted alongside **RepoTriageSentinel** for **Cortensor Hackathon #5**.
All findings below were empirically verified against `openminion==0.1.24` installed cleanly from PyPI into an isolated `.venv` on Windows 11 (Python 3.13).

---

## 1. Building Blocks Tested & What Worked Well

| Building Block | Status | Notes |
|---|---|---|
| `openminion.tool` (`@tool`) | **Works cleanly** | Pydantic v2 args-model generation, `idempotent=True` / `dangerous=True` metadata, and dynamic per-run tool registration & rollback via `ToolRegistry.temporary_registration_scope()` worked on the first try. |
| `Agent(..., output_type=BaseModel)` | **Works cleanly** | Strict Pydantic coercion plus `_extract_json_object()` recovery for prose-wrapped JSON replies is genuinely thoughtful for open-weights models. |
| `APIRuntime.from_config_path` | **Works cleanly (JSON)** | Boots SQLite state store, 10 memory migrations, Alembic baseline, and 106 built-in tools cleanly with explicit `home_root`/`data_root` isolation. |
| `Handoff` & `subagent` | **Works cleanly** | Automatic `transfer_to_<name>` delegate tool synthesis, duplicate-name validation, and bounded `SubagentRunContext` isolation work cleanly. |
| `runtime_posture()` & `tool_inventory_report()` | **Works cleanly** | Great programmatic observability for agent harness diagnostics. |
| Native `providers.cortensor` & `providers.openai` | **Works cleanly** | Clean `hybrid` `tool_call_strategy`, configurable `base_url`, and built-in Cortensor session pooling fields (`session_pool`, `dedicated_session_ids`, `precommit_timeout_seconds`). |

---

## 2. Reproducible Bugs & Developer-Experience Rough Edges Found

### Finding #1 — Config Format Asymmetry: CLI Mentions YAML, `APIRuntime.from_config_path` Only Parses JSON
- **Observation**: `openminion config --help` advertises `import: Import config from a portable YAML file`, which leads new Python SDK users to write a `config.yaml` and pass it to `APIRuntime.from_config_path("config.yaml")`.
- **Actual Result**:
  ```text
  ConfigError: Invalid JSON config at ...\config.yaml: Expecting value: line 1 column 1 (char 0)
  ```
- **Suggested Improvement**: Either detect `.yaml`/`.yml` extensions in `APIRuntime.from_config_path`, or state clearly in the error message and docstring: `"Runtime config files must be JSON (run 'openminion config init' to generate a valid template)"`.

### Finding #2 — `ConfigValidationError` References a Repo-Relative Doc Path Missing from the PyPI Wheel
- **Repro**:
  ```python
  # config.json contains "{}"
  APIRuntime.from_config_path("config.json", home_root=td, data_root=td)
  ```
- **Actual Result**:
  ```text
  openminion.base.config.core.ConfigValidationError: OpenMinionConfig.agents is empty; no default agent is available. Post-CSC configs must populate the 'agents' catalog. See docs/reference/config-shape-migration-2026.md.
  ```
- **Impact**: `docs/reference/config-shape-migration-2026.md` is not packaged inside the `openminion` PyPI wheel (`site-packages/openminion`), so `pip install openminion` users hit a dead reference.
- **Suggested Improvement**: Link to the public hosted docs URL (or print the minimal `{"agents": {"openminion": {"provider": "echo"}}}` snippet inline) and suggest `openminion config init`.

### Finding #3 — Fresh `openminion config init` Immediately Triggers an Identity Error in `openminion doctor --json`
- **Repro**:
  ```bash
  openminion --home-root ./tmp --data-root ./tmp --config ./tmp/config.json config init
  openminion --home-root ./tmp --data-root ./tmp --config ./tmp/config.json doctor --json
  ```
- **Actual Result**: `doctor --json` returns exit code `0`, but emits a check error:
  ```text
  identity bundle root not found: <home_root>\identity\agents\openminion
  ```
- **Suggested Improvement**: Have `openminion config init` also scaffold an empty default identity directory (or downgrade missing identity bundle on a fresh install from error to informational hint).

### Finding #4 — Non-Existent Default Anthropic Model Name in `config init`
- **Observation**: `openminion config init` writes `"anthropic": { "model": "claude-sonnet-5", ... }` as the default Anthropic model identifier.
- **Impact**: Users who simply set `ANTHROPIC_API_KEY` without overriding the model name will receive an upstream 404 model-not-found error.
- **Suggested Improvement**: Default to a current valid Anthropic model ID (e.g., `claude-sonnet-4-20250514` or latest alias).

### Finding #5 — Programmatic `APIRuntime` Construction Without Pre-Shelling Out to `config init`
- **Observation**: `openminion.__all__` exports `OpenMinionConfig` and `APIRuntime`, yet there is no obvious one-line Python constructor such as `APIRuntime.from_config(OpenMinionConfig.default())` or `Agent(provider="cortensor", model=...)` — builders must either shell out to `openminion config init` or hand-craft a full JSON config file on disk.
- **Suggested Improvement**: Expose a first-class `OpenMinionConfig.default(provider=..., model=...)` + `APIRuntime.from_config(cfg)` helper in `openminion.__all__`.

### Finding #6 — Custom `@tool(idempotent=True, dangerous=False)` Still Prompts Under `action_policy.mode="ask"` & Crashes `output_type` Coercion When `approval_callback=None`
- **Repro**: Decorate a read-only custom tool with `@tool(idempotent=True, dangerous=False)`, enable `action_policy: {"mode": "ask", "allow_read_only_without_prompt": true}`, and run `Agent(..., output_type=MyPydanticModel).run(prompt)` without `approval_callback`.
- **Actual Result**:
  1. The custom read-only tool still triggers a policy confirmation prompt (the `@tool` decorator exposes `dangerous` and `idempotent`, but no `read_only=True` parameter recognized by `allow_read_only_without_prompt`).
  2. When `approval_callback=None` (or when `approval_callback` returns `False`), the runtime returns a plain-text message (`"openminion: Policy confirmation required..."` or `"openminion: Confirmation denied. The action was not run."`) as `raw["body"]`, causing `Agent._coerce_output()` to throw `AgentOutputValidationError` instead of surfacing a typed `ApprovalRequiredError` / `ActionDeniedError` (reproduced automatically in `tests/test_sentinel.py::test_approval_callback_blocks_dangerous_write_tool`).
- **Suggested Improvement**: Add `read_only: bool = False` to `@tool` so read-only custom tools respect `allow_read_only_without_prompt`, and raise a dedicated `ApprovalRequiredError` (carrying `approval_id` and `tool_name`) before attempting `output_type` JSON coercion.

### Finding #7 — Multi-Request Internal Orchestration Overhead (`7` HTTP LLM Calls for One 2-Tool Turn)
- **Observation**: Inspecting HTTP traffic to our local OpenAI-compatible server revealed that a single `Agent.run()` turn invoking 2 custom tools triggered **7 sequential `POST /v1/chat/completions` calls** (including internal `submit_output` planning/synthesis calls).
- **Impact**: On decentralized inference backends like Cortensor Portal where per-request round-trip latency is significant, 7 serial LLM calls per simple turn multiplies end-to-end latency.
- **Suggested Improvement**: Provide a lightweight `fast_turn` or `single_loop` execution profile option on `Agent` / `RunProfileOverrides` that bypasses extra internal planner/judge round-trips for focused single-workflow tool agents.
