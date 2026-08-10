"""
Privaro Python SDK
Privacy Infrastructure for Enterprise AI — iCommunity Labs

Usage (protect):
    import privaro
    privaro.init(api_key="prvr_xxx", pipeline_id="uuid")
    result = privaro.protect("Patient: María García, DNI 34521789X")
    print(result.protected)      # "Patient: [NM-0001], DNI [ID-0001]"

Usage (agent sync):
    from privaro.agent import AgentRun
    with AgentRun(api_key="prvr_xxx", pipeline_id="uuid") as run:
        step = run.protect("Analyse contract for Juan García")
        response = your_llm.complete(step.protected_messages)
        final = run.reveal(response)

Usage (agent async / CrewAI):
    from privaro.async_client import AsyncAgentRun
    async with AsyncAgentRun(api_key="prvr_xxx", pipeline_id="uuid") as run:
        step = await run.protect("...")
        final = await run.reveal(await your_llm.acomplete(step.first_content))
"""

from .client import PrivaroClient
from .models import ProtectResult, Detection, ProtectOutputResult
from .exceptions import (
    PrivaroError, AuthError, PipelineNotFoundError, OutputScanningDisabledError,
)
from .agent import AgentRun, PrivaroCallbackHandler

__version__ = "0.5.0"
__all__ = [
    "PrivaroClient",
    "ProtectResult",
    "ProtectOutputResult",
    "Detection",
    "PrivaroError",
    "AuthError",
    "PipelineNotFoundError",
    "OutputScanningDisabledError",
    "AgentRun",
    "PrivaroCallbackHandler",
    "init",
    "protect",
    "protect_output",
    "detect",
    "relay",
    "relay_stream",
]

_default_client: "PrivaroClient | None" = None


def init(
    api_key: str,
    pipeline_id: str,
    base_url: str = "https://api.privaro.ai/v1",
    timeout: float = 10.0,
) -> PrivaroClient:
    """
    Initialize the default Privaro client.

    Args:
        api_key:     Your Privaro API key (starts with prvr_)
        pipeline_id: UUID of your active pipeline
        base_url:    Proxy URL (default: production)
        timeout:     Request timeout in seconds
    """
    global _default_client
    _default_client = PrivaroClient(
        api_key=api_key,
        pipeline_id=pipeline_id,
        base_url=base_url,
        timeout=timeout,
    )
    return _default_client


def _get_config() -> dict:
    """Internal: return current default client config."""
    if _default_client is None:
        return {}
    return {
        "api_key": _default_client.api_key,
        "pipeline_id": _default_client.pipeline_id,
        "base_url": _default_client.base_url,
    }


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
    """Detect and tokenize PII in a prompt."""
    return _require_client().protect(
        prompt=prompt, mode=mode, reversible=reversible,
        agent_mode=agent_mode, include_detections=include_detections,
    )


def detect(prompt: str) -> "ProtectResult":
    """Detect PII without masking (analysis mode)."""
    return _require_client().detect(prompt=prompt)


def protect_output(
    response_text: str,
    mode: str = "tokenise",
    reversible: bool = True,
    agent_mode: bool = False,
    include_detections: bool = True,
    conversation_id: str = None,
) -> "ProtectOutputResult":
    """
    Scan and mask PII in your own LLM's response text (output direction).
    Requires the pipeline to have output_scanning_enabled — see
    PrivaroClient.protect_output() for full details and
    OutputScanningDisabledError.
    """
    return _require_client().protect_output(
        response_text=response_text, mode=mode, reversible=reversible,
        agent_mode=agent_mode, include_detections=include_detections,
        conversation_id=conversation_id,
    )


def relay(messages, **kwargs):
    """Full-cycle relay: protect, call your configured LLM, de-tokenise. See PrivaroClient.relay()."""
    return _require_client().relay(messages, **kwargs)


def relay_stream(messages, **kwargs):
    """Streamed full-cycle relay. See PrivaroClient.relay_stream()."""
    return _require_client().relay_stream(messages, **kwargs)
