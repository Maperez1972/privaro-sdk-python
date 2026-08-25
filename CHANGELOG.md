# Changelog

## 0.6.0 — 2026-08-25

Privaro Ingest support (Fase 1 of the RAG expansion plan). New
`protect_document()` on `PrivaroClient` — protects a whole document
(e.g. before indexing it into a vector store for RAG) rather than a
single chat prompt. Chunking happens server-side, after tokenisation,
so chunk boundaries never split a Privaro token across two chunks.

Handles the server's async job path transparently: large documents may
be processed as a background job; this method polls until the job
finishes, so callers always get back a single, finished result. Raises
`PrivaroError` on a failed job or on a polling timeout.

New: `DocumentChunk`, `ProtectDocumentResult` dataclasses.

Depends on the corresponding backend endpoints
(`POST/GET /v1/proxy/protect-document`) being deployed to have any
effect — safe to install regardless, same as any forward-compatible
addition.

## 0.5.0 — 2026-08-10

Output-direction PII detection. Until now the SDK (and the proxy) only
ever scanned text going *into* an LLM. Direct production evidence showed
the gap: `conversation_messages` had 1,175 PII detections across 76 input
messages and zero across 78 output messages, and `pipelines.total_leaked`
read 0 across every pipeline. `relay()`/`relay_stream()` already scan the
LLM response inline (Privaro makes the LLM call itself there), but
customers who call `protect()` and then hit their own LLM directly had no
equivalent — until now.

- **Added `PrivaroClient.protect_output(response_text, ...)`** and the
  module-level `privaro.protect_output(...)` — calls the new
  `POST /v1/proxy/protect-output` endpoint to scan/mask PII in your LLM's
  raw response text before you return it to your own end user. Same
  `mode`/`reversible`/`conversation_id`/`idempotency_key` contract as
  `protect()` — pass the same `conversation_id` you used for the matching
  `protect()` call so tokens replace consistently across the turn.
- **Added `ProtectOutputResult`** (`privaro.models`) — mirrors
  `ProtectResult` but adds `.scan_mode` (`"shadow"` | `"enforce"`,
  reflecting the pipeline's dashboard setting) and `.response_modified`.
- **Added `OutputScanningDisabledError`** — raised (not a silent
  passthrough) when the target pipeline hasn't opted into output
  scanning (`pipeline.output_scanning_enabled=false`). Enable it per
  pipeline in the dashboard: Pipelines → Settings → Output scanning.
- No breaking changes to existing methods.

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
