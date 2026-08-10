# Privaro Python SDK

**Privacy Infrastructure for Enterprise AI — iCommunity Labs**

The Privaro SDK intercepts prompts and agent steps, tokenises PII before any LLM call, and generates a blockchain-certified audit trail per interaction.

```bash
pip install privaro
pip install privaro[async]   # for AsyncAgentRun + CrewAI support
```

---

## Quick Start

### Protect a prompt

```python
import privaro

privaro.init(
    api_key="prvr_your_key",
    pipeline_id="your-pipeline-uuid"
)

result = privaro.protect("Patient: María García, DNI 34521789X, Tel: 612 345 678")
print(result.protected)
# "Patient: [NM-0001], DNI [ID-0001], Tel: [PH-0001]"

response = your_llm.complete(result.protected)   # LLM never sees real PII
```

---

## Full-cycle relay

Let Privaro protect the messages, call your configured LLM (the key you
set in `/app/admin/providers`), and de-tokenise the response for you.

### `relay()` — single response

```python
result = privaro.relay([
    {"role": "user", "content": "Soy Juan Pérez, ¿podéis confirmarme mi cita?"}
])
print(result["response"])  # already de-tokenised, ready to show
```

### `relay_stream()` — for chat UIs

Yields text deltas as the LLM generates them (SSE under the hood).
Deltas are already de-tokenised — never a raw token, safe to render
directly.

```python
for delta in privaro.relay_stream([
    {"role": "user", "content": "Soy Juan Pérez, ¿podéis confirmarme mi cita?"}
]):
    print(delta, end="", flush=True)
```

Supported for streaming today: OpenAI, Azure OpenAI, Anthropic. Other
providers raise `PrivaroError` — use `relay()` (non-streaming) for those.
`idempotency_key` is not supported on `relay_stream()` (replaying a
completed stream doesn't have the same semantics as retrying a short
response) — use `relay()` if you need idempotent retries.

### Consistent tokens across turns — `conversation_id`

Pass your own conversation/session id to `protect()` or `relay()`/`relay_stream()`
and the same PII value always gets the same token within that conversation:

```python
result = privaro.relay(messages, conversation_id="your-session-id")
```

---

## Output-direction scanning — `protect_output()`

`relay()`/`relay_stream()` already scan the LLM's response for you
(Privaro makes the LLM call itself there). If instead you call
`protect()` and then hit your own LLM directly, use `protect_output()`
to scan that response before returning it to your end user — RAG
retrieval, tool-call results, and model memorization can all leak PII
that was never in the original prompt.

Requires the pipeline to have output scanning enabled (dashboard:
Pipelines → Settings → Output scanning) — otherwise raises
`OutputScanningDisabledError` rather than silently skipping the scan.

```python
result = privaro.protect_output(
    llm_response_text,
    conversation_id="your-session-id",  # same id used for protect()
)
print(result.protected)       # send this to your end user
print(result.scan_mode)       # "shadow" (informational) | "enforce"
print(result.response_modified)
```

---

## Agent Support

### Sync — AgentRun (LangChain, direct)

```python
from privaro.agent import AgentRun

with AgentRun(api_key="prvr_...", pipeline_id="...") as run:
    # Step 1: protect before LLM
    step = run.protect([
        {"role": "user", "content": "Review contract for Juan García, IBAN ES91 2100 0418 4502 0005 1332"}
    ])
    
    # Step 2: send protected messages to LLM
    response = your_llm.complete(step.protected_messages)
    
    # Step 3: detokenise final output
    final = run.reveal(response)
    print(f"Risk score: {step.risk_score}")    # 0.0–1.0
    print(f"PII detected: {step.total_pii_detected}")
```

### Async — AsyncAgentRun (CrewAI, asyncio, n8n)

```python
import asyncio
from privaro.async_client import AsyncAgentRun

async def analyse_document(text: str) -> str:
    async with AsyncAgentRun(
        api_key="prvr_...",
        pipeline_id="...",
        agent_framework="crewai",
    ) as run:
        step = await run.protect(text)
        response = await your_llm.acomplete(step.first_content)
        return await run.reveal(response)

result = asyncio.run(analyse_document("Client: Ana López, DNI 87654321X"))
```

### LangChain Callback Handler

```python
from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor
from privaro.agent import PrivaroCallbackHandler
import privaro

privaro.init(api_key="prvr_...", pipeline_id="...")

handler = PrivaroCallbackHandler(agent_name="contract-agent")
llm = ChatOpenAI(model="gpt-4", callbacks=[handler])
agent_executor = AgentExecutor(agent=agent, tools=tools, callbacks=[handler])

# All prompts and tool outputs are automatically protected
result = agent_executor.invoke({"input": "Analyse this contract for María García"})
```

### CrewAI Tool

```python
from privaro.async_client import CrewAIPrivaroTool
from crewai import Tool

class ContractAnalyser(CrewAIPrivaroTool):
    name = "Contract Analyser"
    description = "Analyses contracts with built-in PII protection"

    async def _execute(self, protected_input: str, run) -> str:
        # protected_input has PII tokenised — safe to send to LLM
        return await your_llm.acomplete(protected_input)

tool = ContractAnalyser(api_key="prvr_...", pipeline_id="...")
```

---

## ProtectResult

```python
result = privaro.protect("...")

result.protected        # Tokenised prompt — send this to your LLM
result.original         # Original text (never sent to Privaro servers)
result.has_pii          # True if PII was detected
result.is_safe          # True if all PII masked, no leaks
result.risk_level       # "high" | "medium" | "low"
result.risk_score       # 0.0–1.0
result.gdpr_compliant   # True if all critical PII was masked
result.total_detected   # Count of PII entities found
result.total_masked     # Count of PII entities masked
result.processing_ms    # Latency in milliseconds
result.audit_log_id     # Supabase audit log UUID
result.summary()        # One-line log string
```

---

## Exceptions

```python
from privaro.exceptions import (
    PrivaroError,                # Base exception
    AuthError,                   # Invalid or missing API key
    PipelineNotFoundError,       # Pipeline UUID not found
    PolicyBlockError,            # Request blocked by policy
    RateLimitError,               # Too many requests
    ProxyUnavailableError,        # Cannot reach proxy
    OutputScanningDisabledError,  # protect_output() called on a pipeline
                                  # that hasn't enabled output scanning
)

try:
    result = privaro.protect("...")
except PolicyBlockError:
    # PII blocked by policy — do not proceed
    pass
except AuthError:
    # Check API key
    pass
```

---

## Requirements

- Python 3.9+
- No required dependencies (uses `urllib` only for sync client)
- `aiohttp>=3.8` for async support (`pip install privaro[async]`)

---

## Links

- Docs: [privaro.ai/docs](https://privaro.ai/docs)
- Dashboard: [privaro.ai/app](https://privaro.ai/app)
- Issues: [github.com/Maperez1972/privaro-sdk-python](https://github.com/Maperez1972/privaro-sdk-python)
- Partners: [partners@privaro.ai](mailto:partners@privaro.ai)
