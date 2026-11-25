# Ready-to-Submit Upstream Patches for `OpenMinion/openminion` (`v0.1.24`)

Each `.patch` file below was generated directly against the unmodified `openminion==0.1.24` package source and verified with `git apply --check` (both individually and combined sequentially) plus `py_compile`.

| Patch | Target File(s) | Severity | Upstream PR | Summary |
|---|---|---|---|---|
| [0001-cortensor-enable-fallback-tool-calls-and-http-reuse.patch](./0001-cortensor-enable-fallback-tool-calls-and-http-reuse.patch) | `src/openminion/modules/llm/providers/cortensor/adapter.py` | **S-Tier (Cortensor)** | [**#862**](https://github.com/openminion/openminion/pull/862) (`Source accepted` · `18/18` CI) | Replaces hardcoded `fallback_enabled=False` (`:470`) with `bool(request.tools and supports_fallback_tool_calling(tool_call_strategy))` so Cortensor `/api/v2/completions` tool calls actually parse; passes `http_client=http_client_for_config(...)` in `_complete_via_openai_chat_mode` (`:261-279`). |
| [0002-handoff-shared-tool-reuse-and-callback-forwarding.patch](./0002-handoff-shared-tool-reuse-and-callback-forwarding.patch) | `src/openminion/api/agent.py`, `src/openminion/api/handoff.py` | **S-Tier (SDK Core)** | Patch archive (overlaps upstream `#776`) | Fails fast at `Agent.__init__` when a `Handoff` target declares temporary `@tool`s on the parent's shared `APIRuntime`, deduplicates already-registered tools in nested same-thread turns, and propagates `approval_callback`, `timeout_seconds`, `cancel_event`, and `on_delta` into `handoff.target.run()/run_stream()`. |
| [0003-policy-windows-skip-posix-world-writable-check.patch](./0003-policy-windows-skip-posix-world-writable-check.patch) | `src/openminion/modules/policy/diagnostics/security.py` | **A-Tier (Windows)** | [**#863**](https://github.com/openminion/openminion/pull/863) (`Source accepted` · `18/18` CI) | Skips POSIX `stat.S_IWOTH` checks on Windows (`os.name == "nt"`), eliminating 3 false-positive `Path is world-writable (0o666/0o777)` / `chmod 750 / 640` warnings in `openminion doctor`. |
| [0004-config-default-channel-and-wheel-doc-url.patch](./0004-config-default-channel-and-wheel-doc-url.patch) | `src/openminion/base/config/core.py`, `src/openminion/base/config/parser/{profiles,payload,runtime}.py` | **A-Tier (Config DX)** | [**#864**](https://github.com/openminion/openminion/pull/864) (`Source accepted` · `18/18` CI · `default_channel`) | Defaults `AgentProfileConfig.default_channel` to `"console"` (preventing `RuntimeError: inbound authenticity denied (reason=invalid_channel)` under programmatic `APIRuntime.from_config`), and replaces dead wheel-relative `docs/reference/config-shape-migration-2026.md` links with `https://www.openminion.com/docs/`. |
| [0005-agent-typed-approval-error-before-output-coercion.patch](./0005-agent-typed-approval-error-before-output-coercion.patch) | `src/openminion/api/agent.py` | **A-Tier (Typed API)** | Patch archive | Raises a dedicated `AgentApprovalRequiredError` (with `denied`, `command_id`, `raw_text`, `metadata`) before calling `_coerce_output()` whenever a structured-output turn stops on `policy_confirmation_prompt` / `brain_status="waiting_user"`. |

## Applying Against an `OpenMinion/openminion` Checkout

```bash
git clone https://github.com/OpenMinion/openminion.git
cd openminion
git apply --check /path/to/patches/0001-cortensor-enable-fallback-tool-calls-and-http-reuse.patch
git apply /path/to/patches/0001-cortensor-enable-fallback-tool-calls-and-http-reuse.patch
```

See [SDK_FEEDBACK_REPORT.md](../SDK_FEEDBACK_REPORT.md) for full root-cause analyses and minimal standalone reproduction scripts for every patch.
