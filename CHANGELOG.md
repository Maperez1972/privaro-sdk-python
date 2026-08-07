# Changelog

## 0.4.0 — 2026-08-07

Found during a full backend integration audit of Context Optimization (privaro-proxy PR #1): the API gained the ability to compress tokenised prompts/messages before sending them to your LLM, but the SDK had no way to request or read it.

- **Added `optimize_context: bool = False` to `PrivaroClient.protect()`, `AgentRun.protect()` (sync), and `AsyncAgentRun.protect()`** — three separate call sites, none sharing a common base. Compresses tokenised content before returning it, reducing tokens sent to your LLM. Never touches PII tokens (`[XX-0001]`) — verified end-to-end against real documents before release.
- **Added `compression_stats: Optional[Dict[str, Any]] = None`** to `ProtectResult`, `StepResult`, and `AsyncStepResult` — populated only when `optimize_context=True` was passed and the compressor actually ran.
- No breaking changes — new parameter defaults to `False`, new field defaults to `None`.

## 0.3.0 — 2026-07-24

Prompted by a real integration in progress (Octupus/Robin AI), and a
follow-up audit after fixing the same class of issues in the JS SDK.

### Fixed — critical

- **`AgentRun` (sync, `privaro.agent`) and `AsyncAgentRun` (`privaro.async_client`)
  sent `Authorization: Bearer <key>` to the proxy, which only ever checks
  `X-Privaro-Key`** (see the proxy's own `agent.py` docstring). Every call
  made through either of these — `start()`, `protect()`, `reveal()`,
  `end()` — has been failing with 401 since this SDK's first release.
  Fixed in both. Added a regression test asserting the real header sent.

### Fixed

- `PrivaroClient.DEFAULT_BASE_URL`, `AgentRun`'s default `base_url`, and
  `AsyncAgentRun.BASE_URL` all pointed at the old Railway auto-generated
  domain (`privaro-proxy-production.up.railway.app`) instead of the
  custom domain (`api.privaro.ai`). Both still resolve today, but the SDK
  should point at the real one.

### Added

- **`PrivaroClient.relay(messages, ...)`** — full-cycle relay (protect →
  call your configured LLM → de-tokenise response), calling
  `/v1/relay/complete`. Did not exist before this release.
- **`PrivaroClient.relay_stream(messages, ...)`** — same, but streamed as
  the LLM generates it (SSE under the hood), yielding already
  de-tokenised text deltas. Supported for OpenAI, Azure OpenAI, and
  Anthropic today; other providers raise `PrivaroError`.
- `conversation_id` and `idempotency_key` parameters on `protect()` and
  `relay()` (previously only implicit via `AgentRun`'s own conversation
  scoping).
- Module-level `privaro.relay()` / `privaro.relay_stream()` shortcuts,
  mirroring the existing `privaro.protect()` / `privaro.detect()`.
- Tests: 8 new cases covering `relay()`, `relay_stream()` (including the
  critical case of a single SSE event split across two raw network
  chunks), and the auth header regression above. All 18 tests pass.

## 0.2.0

(Prior release — no changelog kept before this point.)
