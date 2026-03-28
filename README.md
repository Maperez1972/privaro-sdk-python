# Privaro Python SDK

**Privacy Infrastructure for Enterprise AI** — Official Python SDK by [iCommunity Labs](https://privaro.ai)

Protect PII in AI prompts with one line of code. Every interaction is tokenized, audited, and blockchain-certified.

---

## 🚀 Why Privaro

Control data before AI processing.

---


## 🔥 Example (OpenAI)

```python
from openai import OpenAI
from privaro import Privaro

client = OpenAI()
privaro = Privaro(api_key="YOUR_API_KEY")

input_text = "My name is John Doe and my IBAN is ES76..."

protected = privaro.protect(prompt=input_text)

response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role":"user","content":protected["protected_prompt"]}]
)

print(response)
```

---

## ❌ Without Privaro

Raw data → model

## ✅ With Privaro

Tokenized → safe → auditable

---

## 🤖 Agents

Supports multi-step agent protection.

---

## 🔗 Related

- Proxy
- JS SDK

---

## ⚡ Install

```bash
pip install privaro
```

No required dependencies — uses Python stdlib only.

```bash
# Optional: async support
pip install privaro[async]
```

---

## Quick Start

```python
import privaro

# Initialize once (e.g., at app startup)
privaro.init(
    api_key="prvr_your_api_key",
    pipeline_id="your-pipeline-uuid",
)

# Protect a prompt before sending to any LLM
result = privaro.protect("Patient: María García, DNI 34521789X, IBAN ES91 2100...")

print(result.protected)      # "Patient: [NM-0001], DNI [ID-0001], IBAN [BK-0001]..."
print(result.risk_score)     # 0.847
print(result.risk_level)     # "high"
print(result.gdpr_compliant) # True

# Send protected prompt to your LLM — no PII ever reaches the model
response = openai.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": result.protected}]
)
```

---

## Usage Patterns

### Protect + LLM (full pipeline)

```python
import privaro
import openai

privaro.init(api_key="prvr_xxx", pipeline_id="uuid")

def ask_ai(user_input: str) -> str:
    # 1. Protect PII
    protected = privaro.protect(user_input)

    if not protected.is_safe:
        raise ValueError(f"PII leak detected: {protected.leaked} entities exposed")

    # 2. Call LLM with protected prompt
    response = openai.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": protected.protected}]
    )

    return response.choices[0].message.content
```

### Detect only (analysis mode)

```python
result = privaro.detect("Call me at 612 345 678, email: user@company.es")

for detection in result.detections:
    print(f"{detection.type}: {detection.severity} ({detection.detector})")
# phone: high (regex)
# email: high (regex)
```

### Agent mode (stricter policies)

```python
result = privaro.protect(
    prompt=agent_input,
    agent_mode=True,   # Applies stricter policy preset
)
```

### Multiple clients (multiple pipelines)

```python
from privaro import PrivaroClient

legal_client = PrivaroClient(api_key="prvr_xxx", pipeline_id="legal-pipeline-uuid")
hr_client = PrivaroClient(api_key="prvr_xxx", pipeline_id="hr-pipeline-uuid")

legal_result = legal_client.protect(contract_text)
hr_result = hr_client.protect(employee_record)
```

### Async support

```python
from privaro.async_client import AsyncPrivaroClient

client = AsyncPrivaroClient(api_key="prvr_xxx", pipeline_id="uuid")

async def process(prompt: str):
    result = await client.protect(prompt)
    return result.protected
```

### Error handling

```python
from privaro.exceptions import AuthError, PolicyBlockError, ProxyUnavailableError

try:
    result = privaro.protect(prompt)
except PolicyBlockError as e:
    # Request blocked by policy (e.g., health data on non-approved provider)
    logger.warning(f"Request blocked: {e}")
    return "Request cannot be processed — sensitive data detected."
except ProxyUnavailableError:
    # Fallback: log and fail safely
    logger.error("Privaro proxy unavailable")
    raise
except AuthError:
    logger.error("Invalid Privaro API key")
    raise
```

---

## ProtectResult Reference

| Property | Type | Description |
|---|---|---|
| `result.protected` | str | Prompt with PII replaced by tokens |
| `result.original` | str | Original prompt (local only) |
| `result.risk_score` | float | 0.0–1.0 composite risk score |
| `result.risk_level` | str | "high" / "medium" / "low" |
| `result.gdpr_compliant` | bool | True if no PII leaked |
| `result.is_safe` | bool | True if all PII masked |
| `result.has_pii` | bool | True if any entities detected |
| `result.total_detected` | int | Total PII entities found |
| `result.total_masked` | int | Entities successfully masked |
| `result.leaked` | int | Entities that passed through |
| `result.detections` | list[Detection] | Per-entity details |
| `result.audit_log_id` | str | Supabase audit log UUID |
| `result.processing_ms` | int | Proxy latency in ms |
| `result.summary()` | str | One-line log summary |

---

## Detection Reference

| Property | Values |
|---|---|
| `detection.type` | `dni` `iban` `email` `full_name` `phone` `health_record` `credit_card` `ip_address` `date_of_birth` |
| `detection.severity` | `critical` `high` `medium` `low` |
| `detection.action` | `tokenised` `anonymised` `blocked` |
| `detection.detector` | `regex` `presidio` |
| `detection.confidence` | 0.0–1.0 |
| `detection.is_high_risk` | bool |

---

## Blockchain Verification

Every `protect()` call creates an immutable audit entry certified on **Fantom Opera Mainnet** via iBS. Verify any event at:

```
https://checker.icommunitylabs.com/check/fantom_opera_mainnet/{tx_hash}
```

Access the TX hash from your Privaro dashboard → Audit Logs → ⛓️ badge.

---

## Requirements

- Python 3.9+
- Zero required dependencies (uses `urllib` from stdlib)
- Optional: `aiohttp>=3.9` for async support

---

## License

MIT — © 2026 by iCommunity Labs · [privaro.ai](https://privaro.ai)
[icommunity.io](https://icommunity.io)
