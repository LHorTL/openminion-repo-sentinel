# OpenMinion 0.1.24 Developer Field Report & Verified Patch Suite

Submitted alongside **RepoTriageSentinel** for **Cortensor Hackathon #5**.
Every finding below was empirically reproduced against unmodified **`openminion==0.1.24`** installed from PyPI into an isolated `.venv` on **Windows 11 (Python 3.13)**, cross-checked line-by-line against `site-packages/openminion/`, backed by automated regression tests in [`tests/test_sentinel.py`](./tests/test_sentinel.py), and paired with ready-to-apply unified patches in [`patches/`](./patches/README.md).

---

## 1. OpenMinion 0.1.24 Building Blocks Tested

| Building Block | Observed Status | Empirically Verified Behavior |
|---|---|---|
| `openminion.tool` (`@tool`) | **Works cleanly (with `min_scope="READ_ONLY"`)** | Pydantic v2 args-model generation, `min_scope="READ_ONLY"` (zero approval prompts under `action_policy.mode="ask"`), `dangerous=True` (enforces `approval_callback`), and temporary per-run registration/rollback work cleanly once `min_scope="READ_ONLY"` is declared per `tools/decorator.py:321-337`. |
| `Agent(..., output_type=BaseModel)` | **Works well, with 1 policy-denial rough edge** | Strict Pydantic v2 validation plus `_extract_json_object()` recovery for prose-wrapped JSON works cleanly on normal completions, but collides with plain-text confirmation/denial replies (see Finding #3). |
| `APIRuntime.from_config` | **Works with `default_channel="console"` workaround** | Programmatic construction without shelling out to `openminion config init` boots SQLite state, 10 memory migrations, and 106 built-in tools cleanly — **only** when `default_channel="console"` is passed explicitly (see Finding #4). |
| `Handoff` (`transfer_to_<name>`) | **Works ONLY with a dedicated child `APIRuntime`** | Delegate tool synthesis and typed peer `output_type` handback work when the Handoff target owns its own `APIRuntime`; sharing the parent's `APIRuntime` with decorated `@tool`s fails mid-turn with an opaque `EXEC_ERROR`, and parent turn callbacks are not forwarded (see Finding #2). |
| `subagent(...)` | **Works cleanly** | Materializes an isolated `SubagentRunContext` (`tool_allowlist`, `typed_result_handback=True`, `parent_transcript_inherited=False`) and returns typed Pydantic output cleanly on distinct read-only tools. |
| `Agent.run_stream(on_delta=...)` | **Works cleanly** | Emits rich `PhaseStatus` (`analyzing`, `working`, `executing`), `budget_event`, `tool_started`, and `tool_completed` progress events (49 events observed in a full triage turn). |
| `MemoryBundle` portability (`export_bundle`, `save_bundle`, `load_bundle`, `import_bundle`) | **Works cleanly** | Clean JSON round-trip (`memory_bundle.v1`) enabling cross-run triage history persistence and regression diffing across runs. |
| `providers.cortensor` (direct router `/api/v2/completions`) | **Broken for fallback tool calls in `0.1.24`** | Prompt builder injects the `{"tool_calls":[...]}` JSON contract, but `_parse_response_payload` hardcodes `fallback_enabled=False` and drops all completion-mode tool calls (see Finding #1). Use `cortensor-portal` (`openai` adapter at `https://api.cortensor.app/v1`) until patched. |
| `openminion doctor --json` & `runtime_posture()` | **Useful, with Windows false positives** | Great programmatic observability (`runtime_posture()`, `tool_inventory_report(readiness=True)`), but `doctor --json` emits 3 false-positive POSIX `world-writable` warnings on Windows (see Finding #5). |

---

## 2. Source-Verified Bugs & Ready-to-Submit Fix Patches

### Finding #1 [S-Tier / Cortensor-Native] — `CortensorProvider` Hardcodes `fallback_enabled=False`, Breaking All `/api/v2/completions` Tool Calls (+ Missing `http_client` Reuse)
- **Source Locations**:
  - `openminion/modules/llm/providers/cortensor/adapter.py:470` (`_parse_response_payload`)
  - `openminion/modules/llm/providers/cortensor/adapter.py:616-621` (`_build_completion_prompt`)
  - `openminion/modules/llm/providers/cortensor/adapter.py:261-279` (`_complete_via_openai_chat_mode`)
- **Root Cause**:
  1. In Cortensor direct-router completion mode (`/api/v2/completions`), `_build_completion_prompt()` explicitly injects the fallback tool-calling contract (`{"tool_calls":[{"name":"<tool_name>","arguments":{}}]}`) into the prompt, and `_build_openai_chat_payload()` (`:511-514`) also injects it when `tool_call_strategy="hybrid"` (default).
  2. However, `_parse_response_payload()` accepts `tool_call_strategy` as a parameter (`:453`), never reads it, and passes **`fallback_enabled=False` hardcoded** (`:470`) into `resolve_tool_call_source_precedence(...)`. Because `/api/v2/completions` returns plain text in `choices[0].text` (no native `message.tool_calls`), **100% of tool calls from Cortensor direct-router nodes are silently discarded**.
  3. Separately, `_complete_via_openai_chat_mode()` (`:261-279`) omits `http_client=http_client_for_config(self._http_client, config)` when calling `_post_with_retries()` (unlike `_complete_via_completion_mode()` at `:342`), silently disabling HTTP connection reuse.
- **Minimal Repro** (automated in `tests/test_sentinel.py::test_repro_cortensor_provider_fallback_tool_call_bug`):
  ```python
  import json
  from openminion.modules.llm.providers.behavior import resolve_behavior_profile
  from openminion.modules.llm.providers.cortensor.adapter import CortensorProvider
  from openminion.modules.llm.schemas import LLMRequest, Message

  cp = CortensorProvider()
  req = LLMRequest(
      messages=[Message(role="user", content="inspect repo")],
      tools=[{"name": "inspect_git_repo", "description": "inspect", "input_schema": {"type": "object"}}],
  )
  bp = resolve_behavior_profile(provider="cortensor", model="gpt-oss-20b", base_url="http://127.0.0.1:8080/api/v2/completions")
  assert '"tool_calls"' in cp._build_completion_prompt(req)  # Prompt demands JSON tool_calls

  parsed = cp._parse_response_payload(
      response_payload={"id": "c1", "model": "gpt-oss-20b", "choices": [{"index": 0, "text": json.dumps({"tool_calls": [{"name": "inspect_git_repo", "arguments": {"repo_path": "."}}]}), "finish_reason": "stop"}]},
      request=req, tool_call_strategy="hybrid", fallback_model="gpt-oss-20b", behavior_profile=bp,
  )
  print(parsed["tool_calls"], parsed["tool_call_normalization"])
  ```
- **Actual Result**:
  ```text
  [] {'tool_call_source': 'none', 'tool_call_native_call_count': 0, 'tool_call_attempted_fallback_sources': [], 'tool_call_skipped_fallback_sources': ['choice.text']}
  ```
- **Ready-to-Apply Patch**: [`patches/0001-cortensor-enable-fallback-tool-calls-and-http-reuse.patch`](./patches/0001-cortensor-enable-fallback-tool-calls-and-http-reuse.patch)

---

### Finding #2 [S-Tier / SDK Core] — `Handoff` Traps: Swallowed Shared-Runtime Deadlock Guard, Shared-`@tool` Registration Crash, and Dropped Parent Callbacks
- **Source Locations**:
  - `openminion/modules/tool/registry/__init__.py:92-102` (`temporary_registration_scope`)
  - `openminion/api/agent.py:124-136` (`Agent.__init__`), `openminion/api/agent.py:217-227` (`_register_tools_for_run`)
  - `openminion/api/handoff.py:168-169` (`build_delegate_tool._handler_fn`)
- **Root Cause**:
  1. **Silent construction + swallowed error**: Passing `runtime=rt` to both a parent `Agent` and a `Handoff` target `Agent` with decorated `@tool`s succeeds silently at `Agent.__init__`. Mid-turn, when the LLM calls `transfer_to_<peer>` on a worker thread while the parent holds `temporary_registration_scope()`, `ToolRegistry` raises `RuntimeError("Temporary tool registration in a cross-thread shared-runtime handoff would deadlock; use a separate runtime for the child agent")` — which the tool executor catches and masks as an opaque `{"status": "failed", "error": {"code": "EXEC_ERROR", "message": "Tool execution failed", "details": {"error_type": "RuntimeError"}}}`!
  2. **Same-thread shared `@tool` collision**: Even without cross-thread contention, if a nested agent sharing `rt` declares the same `@tool`-decorated function as an enclosing active turn, `Agent._register_tools_for_run()` unconditionally calls `registry.add(spec)` (`:226`) -> `ToolRuntimeError: Tool already registered: <name>` (reproduced in `tests/test_sentinel.py::test_repro_handoff_shared_tool_collision`).
  3. **Dropped parent turn hooks**: `build_delegate_tool` (`handoff.py:169`) invokes `handoff.target.run(message)` without propagating `approval_callback`, `timeout_seconds`, `cancel_event`, or `on_delta`. Any approval-gated tool inside a Handoff target silently stalls returning `"Policy confirmation required..."` wrapped inside `{"ok": True}`!
- **Workaround in `RepoTriageSentinel`**: Give `security_specialist` its own dedicated `APIRuntime` (`peer_rt`) and exclusively `min_scope="READ_ONLY"` tools (`audit_dependency_and_secret_context`).
- **Ready-to-Apply Patch**: [`patches/0002-handoff-shared-tool-reuse-and-callback-forwarding.patch`](./patches/0002-handoff-shared-tool-reuse-and-callback-forwarding.patch)

---

### Finding #3 [A-Tier / Typed Output Contract] — Policy Confirmation / Denial Collides with `Agent(..., output_type=BaseModel)` Coercion
- **Source Locations**:
  - `openminion/api/agent.py:364-370` (`Agent._run_once`)
  - `openminion/modules/brain/runner/tick/confirmation.py:355-362`
- **Root Cause**: When a `dangerous=True` (or non-`READ_ONLY`) tool requires confirmation under `action_policy.mode="ask"` and either `approval_callback=None` or `approval_callback` returns `False`, `runtime.run_turn()` returns `run_state="completed"` with `metadata["respond_kind"] == "policy_confirmation_prompt"`, `metadata["brain_status"] == "waiting_user"`, and plain-text `body` (`"openminion: Policy confirmation required..."` or `"openminion: Confirmation denied. The action was not run."`). `Agent._run_once()` ignores `respond_kind`/`brain_status` and blindly passes that text to `self._coerce_output(reply_text)`, raising `AgentOutputValidationError` instead of a typed approval/denial exception (reproduced in `tests/test_sentinel.py::test_approval_callback_blocks_dangerous_write_tool`).
- **Ready-to-Apply Patch**: [`patches/0005-agent-typed-approval-error-before-output-coercion.patch`](./patches/0005-agent-typed-approval-error-before-output-coercion.patch)

---

### Finding #4 [A-Tier / Programmatic Config DX] — `APIRuntime.from_config(OpenMinionConfig.from_dict(...))` Crashes on Turn 1 When `default_channel` Is Omitted
- **Source Locations**:
  - `openminion/base/config/core.py:124` (`AgentProfileConfig.default_channel: str = ""`)
  - `openminion/base/config/parser/profiles.py:77` (`default_channel=agent_config.get("default_channel", "")`)
  - `openminion/services/gateway/security.py:132` (`enforce_inbound_authenticity`)
- **Root Cause**: `openminion config init` writes `"default_channel": "console"` (`cli/commands/config.py:38`), so CLI-initialized configs work. By contrast, constructing a programmatic config via `OpenMinionConfig.from_dict({"agents": {"openminion": {"provider": "openai"}}})` and booting `APIRuntime.from_config(config=cfg, home_root=p, data_root=p)` boots cleanly and then **crashes on the very first turn** with:
  ```text
  RuntimeError: inbound authenticity denied (reason=invalid_channel, mode=warn)
  ```
  (Reproduced automatically in `tests/test_sentinel.py::test_repro_programmatic_from_config_missing_default_channel_bug`.)
- **Ready-to-Apply Patch**: [`patches/0004-config-default-channel-and-wheel-doc-url.patch`](./patches/0004-config-default-channel-and-wheel-doc-url.patch)

---

### Finding #5 [A-Tier / Windows Diagnostics] — 3 False-Positive `Path is world-writable (0o666/0o777)` Warnings in `openminion doctor` on Windows 11 (+ Fresh `identity.bundle` Warning)
- **Source Locations**:
  - `openminion/modules/policy/diagnostics/security.py:379-390` (`_permission_finding`)
  - `openminion/cli/commands/doctor.py:516-526` (`_build_identity_bundle_check`)
- **Actual Result on Windows 11** (verified on fresh `openminion config init` followed by `openminion doctor --json` — exit code `0`, `summary.ok=True`, `warn=6`):
  1. **3 Windows false positives**: `security.filesystem.config_permissions` (`0o666`), `security.filesystem.storage_permissions` (`0o777`), and `security.filesystem.memory_permissions` (`0o777`) all fire `"Path is world-writable"` with remediation `"Restrict permissions (for example chmod 750 on dirs, 640 on files)."` because CPython on Windows synthesizes `st_mode` from the DOS read-only bit, never NTFS ACLs.
  2. **Fresh identity warning**: `identity.bundle` immediately emits `status="warn"` (`"Identity profile is missing in IdentityCtl for agent 'openminion'."`) with `details.bundle_diagnostics.errors: ["identity bundle root not found: ..."]` even right after `openminion config init`.
- **Ready-to-Apply Patch**: [`patches/0003-policy-windows-skip-posix-world-writable-check.patch`](./patches/0003-policy-windows-skip-posix-world-writable-check.patch)

---

### Finding #6 [A-Tier / Cortensor Latency Impact] — 7+ Sequential LLM Calls for a Single Read-Only Tool Turn
- **Observation**: Tracing HTTP traffic with a schema-compliant local OpenAI server (answering all internal `submit_output` structured-output schemas with zero validation retries) showed that even a **single `min_scope="READ_ONLY"` tool turn** triggers **7 sequential `POST /v1/chat/completions` calls**:
  1. `#1` entry / tool-call decision
  2. `#2` internal freshness-routing classifier (`submit_output`: `intent/time_sensitive/needs_live_data`)
  3. `#3` second freshness-routing classifier call (`freshness_classify=2` in turn metadata!)
  4. `#4` post-tool continuation step
  5. `#5` second continuation step
  6. `#6` reflection check (`submit_output`: `status/remaining_work/blocking_reason`)
  7. `#7` final judge (`submit_output`: `satisfied/next_action/final_answer/post_completion_critique`)
  Across our full 3-agent workflow (orchestrator + `security_specialist` Handoff + `release_brief_writer` subagent), OpenMinion executes **26 sequential LLM calls** (15 internal `submit_output` calls).
- **Cortensor Impact**: On decentralized Cortensor inference (where OpenMinion's own `setup_catalog.py:141` configures `timeout_seconds=480` for Cortensor Portal and `420` for Cortensor Router), 7 serial LLM calls per single-tool turn multiply end-to-end wall-clock latency by 3–4× compared to a standard 2-call ReAct loop, and duplicate `freshness_classify` calls add avoidable round-trips.
- **Suggested Improvement**: Add a `fast_turn` / `single_loop` profile in `RunProfileOverrides` (skipping redundant `freshness_classify` / `reflect` / `judge` round-trips for bounded tool workflows), and investigate why `freshness_classify` runs twice on a single turn.

---

### Finding #7 [B-Tier / Packaging & Config DX] — Dead Repo-Relative Doc Path in PyPI Wheel & YAML/JSON Config Format Asymmetry
- **Source Locations**:
  - 7 references to `docs/reference/config-shape-migration-2026.md`: `base/config/core.py:348,401`, `base/config/parser/payload.py:65`, `base/config/parser/profiles.py:71`, `base/config/parser/runtime.py:101,107,113` (not packaged inside the PyPI wheel — 0 matching files in `site-packages/`).
  - `cli/commands/config.py:189,566` (`config import` parses YAML via `yaml.safe_load`) vs `base/config/io.py:59-61` (`APIRuntime.from_config_path` parses JSON only and raises `ConfigError: Invalid JSON config`).
- **Ready-to-Apply Patch**: [`patches/0004-config-default-channel-and-wheel-doc-url.patch`](./patches/0004-config-default-channel-and-wheel-doc-url.patch) (replaces all 7 dead wheel-relative doc references with `https://www.openminion.com/docs/`).
