"""
Privaro Python SDK
Privacy Infrastructure for Enterprise AI — iCommunity Labs

Usage (protect):
    import privaro
    privaro.init(api_key="prvr_xxx", pipeline_id="uuid")
    result = privaro.protect("Patient: María García, DNI 34521789X")
    print(result.protected)      # "Patient: [NM-0001], DNI [ID-0001]"

Usage (agent):
    from privaro.agent import AgentRun
    with AgentRun(api_key="prvr_xxx", pipeline_id="uuid") as run:
        step = run.protect([{"role": "user", "content": "Call customer John Smith"}])
        # send step.protected_messages to LLM...
        final = run.reveal(llm_response)
"""

from .client import PrivaroClient
from .models import ProtectResult, Detection
from .exceptions import PrivaroError, AuthError, PipelineNotFoundError
from .agent import AgentRun, PrivaroCallbackHandler

__version__ = "0.2.0"
__all__ = [
    "PrivaroClient",
    "ProtectResult",
    "Detection",
    "PrivaroError",
    "AuthError",
    "PipelineNotFoundError",
    "init",
    "protect",
    "detect",
]

# ── Module-level default client ───────────────────────────────────────────────
_default_client: "PrivaroClient | None" = None


def init(
    api_key: str,
    pipeline_id: str,
    base_url: str = "https://privaro-proxy-production.up.railway.app/v1",
    timeout: float = 10.0,
) -> PrivaroClient:
    """
    Initialize the default Privaro client.

    Args:
        api_key:     Your Privaro API key (starts with prvr_)
        pipeline_id: UUID of your active pipeline
        base_url:    Proxy URL (default: production)
        timeout:     Request timeout in seconds

    Returns:
        PrivaroClient instance (also set as module default)

    Example:
        privaro.init(
            api_key="prvr_abc123",
            pipeline_id="c93aed87-b440-4de0-bb21-54a938e475f2"
        )
    """
    global _default_client
    _default_client = PrivaroClient(
        api_key=api_key,
        pipeline_id=pipeline_id,
        base_url=base_url,
        timeout=timeout,
    )
    return _default_client


def _require_client() -> "PrivaroClient":
    if _default_client is None:
        raise PrivaroError(
            "Privaro not initialized. Call privaro.init(api_key=..., pipeline_id=...) first."
        )
    return _default_client


def protect(
    prompt: str,
    mode: str = "tokenise",
    reversible: bool = True,
    agent_mode: bool = False,
    include_detections: bool = True,
) -> "ProtectResult":
    """
    Detect and tokenize PII in a prompt.

    Args:
        prompt:             Text to protect
        mode:               tokenise | anonymise | block
        reversible:         Store reversible tokens in vault
        agent_mode:         Apply stricter policies for agent pipelines
        include_detections: Include detection details in response

    Returns:
        ProtectResult with .protected, .risk_score, .detections, etc.

    Example:
        result = privaro.protect("Patient: María García, DNI 34521789X")
        llm_response = your_llm.complete(result.protected)
    """
    return _require_client().protect(
        prompt=prompt,
        mode=mode,
        reversible=reversible,
        agent_mode=agent_mode,
        include_detections=include_detections,
    )


def detect(prompt: str) -> "ProtectResult":
    """
    Detect PII without masking (analysis mode).
    Does not store audit logs or tokens.

    Example:
        result = privaro.detect("Call me at 612 345 678")
        for d in result.detections:
            print(d.type, d.confidence)
    """
    return _require_client().detect(prompt=prompt)
