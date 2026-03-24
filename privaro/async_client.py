"""
Privaro SDK — Async Client (optional, requires Python 3.11+)

Usage:
    from privaro.async_client import AsyncPrivaroClient

    client = AsyncPrivaroClient(api_key="prvr_xxx", pipeline_id="uuid")

    async with client:
        result = await client.protect("María García, DNI 34521789X")
"""
import json
from typing import Optional
from .client import PrivaroClient
from .models import ProtectResult
from .exceptions import (
    AuthError, PipelineNotFoundError, PolicyBlockError,
    RateLimitError, ProxyUnavailableError, PrivaroError,
)


class AsyncPrivaroClient(PrivaroClient):
    """
    Async version of PrivaroClient using aiohttp (optional dependency).

    Install with: pip install privaro[async]
    """

    async def _request_async(self, method: str, path: str, payload: dict) -> dict:
        try:
            import aiohttp
        except ImportError:
            raise PrivaroError(
                "aiohttp is required for async support. "
                "Install with: pip install privaro[async]"
            )

        url = f"{self.base_url}{path}"

        async with aiohttp.ClientSession() as session:
            try:
                async with session.request(
                    method, url,
                    json=payload,
                    headers=self._headers(),
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp:
                    body = await resp.json()

                    if resp.status == 401:
                        raise AuthError("Invalid API key.")
                    if resp.status == 404:
                        raise PipelineNotFoundError(f"Pipeline '{self.pipeline_id}' not found.")
                    if resp.status == 429:
                        raise RateLimitError("Rate limit exceeded.")
                    if resp.status >= 400:
                        raise PrivaroError(f"HTTP {resp.status}: {body}")

                    return body

            except aiohttp.ClientConnectorError as e:
                raise ProxyUnavailableError(f"Cannot reach proxy: {e}")

    async def protect(
        self,
        prompt: str,
        mode: str = "tokenise",
        reversible: bool = True,
        agent_mode: bool = False,
        include_detections: bool = True,
    ) -> ProtectResult:
        """Async version of protect()."""
        if not prompt or not prompt.strip():
            return ProtectResult(protected="", original="", request_id="",
                                 audit_log_id=None, gdpr_compliant=True)

        raw = await self._request_async("POST", "/proxy/protect", {
            "pipeline_id": self.pipeline_id,
            "prompt": prompt,
            "options": {
                "mode": mode,
                "reversible": reversible,
                "agent_mode": agent_mode,
                "include_detections": include_detections,
            },
        })
        return self._parse_result(raw, original=prompt)

    async def detect(self, prompt: str) -> ProtectResult:
        """Async version of detect()."""
        if not prompt or not prompt.strip():
            return ProtectResult(protected=prompt, original=prompt, request_id="",
                                 audit_log_id=None, gdpr_compliant=True)

        raw = await self._request_async("POST", "/proxy/detect", {
            "pipeline_id": self.pipeline_id,
            "prompt": prompt,
        })
        result = self._parse_result(
            {**raw, "protected_prompt": prompt, "gdpr_compliant": True},
            original=prompt,
        )
        result.protected = prompt
        return result

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass
