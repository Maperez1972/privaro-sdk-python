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
    "AgentRun",
    "PrivaroCallbackHandler",
    "init",
    "protect",
    "detect",
]

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
