"""
Privaro SDK — Async Agent Client
Supports asyncio, LangChain async, CrewAI, n8n webhooks.
"""
from __future__ import annotations
import json
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass

try:
    import aiohttp
    _HAS_AIOHTTP = True
except ImportError:
    _HAS_AIOHTTP = False

from .models import ProtectResult, Detection
from .exceptions import PrivaroError, AuthError


@dataclass
class AsyncStepResult:
    agent_run_id: str
    step_index: int
    protected_messages: List[Dict]
    total_pii_detected: int
    total_pii_masked: int
    risk_score: float
    gdpr_compliant: bool
    audit_step_id: Optional[str] = None

    @property
    def first_content(self) -> str:
        """Convenience: return content of first protected message."""
        if self.protected_messages:
            return self.protected_messages[0].get("content", "")
        return ""


class AsyncAgentRun:
    """
    Async context manager for agent governance.
    Requires aiohttp: pip install privaro[async]

    Usage:
        async with AsyncAgentRun(api_key="prvr_...", pipeline_id="...") as run:
            step = await run.protect("Analyse contract for Juan García, DNI 12345678X")
            response = await your_llm.acomplete(step.first_content)
            final = await run.reveal(response)

    CrewAI usage:
        from privaro.async_client import AsyncAgentRun

        class PrivaroCrewTool(BaseTool):
            async def _arun(self, query: str) -> str:
                async with AsyncAgentRun(api_key=..., pipeline_id=...) as run:
                    step = await run.protect(query)
                    return step.first_content
    """

    BASE_URL = "https://api.privaro.ai"

    def __init__(
        self,
        api_key: Optional[str] = None,
        pipeline_id: Optional[str] = None,
        base_url: str = BASE_URL,
        agent_name: Optional[str] = None,
        agent_framework: Optional[str] = None,
        timeout: float = 30.0,
    ):
        if not _HAS_AIOHTTP:
            raise ImportError(
                "aiohttp is required for async support. "
                "Install with: pip install privaro[async]"
            )
        # Resolve from module-level init if not provided
        if not api_key or not pipeline_id:
            try:
                from privaro import _default_client
                if _default_client:
                    api_key = api_key or _default_client.api_key
                    pipeline_id = pipeline_id or _default_client.pipeline_id
            except ImportError:
                pass

        if not api_key:
            raise PrivaroError("api_key is required.")
        if not pipeline_id:
            raise PrivaroError("pipeline_id is required.")

        self._api_key = api_key
        self._pipeline_id = pipeline_id
        self._base_url = base_url.rstrip("/")
        self._agent_name = agent_name
        self._agent_framework = agent_framework
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._run_id: Optional[str] = None
        self._step_counter = 0
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self) -> "AsyncAgentRun":
        self._session = aiohttp.ClientSession(
            headers={
                # Fixed 2026-07-24 — same bug as the sync AgentRun: the
                # proxy authenticates with X-Privaro-Key, not Authorization
                # Bearer. Every call made through this async client has
                # been failing with 401 since this SDK's first release.
                "X-Privaro-Key": self._api_key,
                "Content-Type": "application/json",
            },
            timeout=self._timeout,
        )
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        status = "failed" if exc_type else "completed"
        try:
            await self.end(status=status)
        except Exception:
            pass
        if self._session:
            await self._session.close()

    async def _request(self, method: str, path: str, body: Optional[dict] = None) -> dict:
        url = f"{self._base_url}{path}"
        async with self._session.request(method, url, json=body) as resp:
            data = await resp.json()
            if resp.status == 401:
                raise AuthError("Invalid API key.")
            if resp.status >= 400:
                raise PrivaroError(f"API error {resp.status}: {data}")
            return data

    async def start(
        self,
        agent_name: Optional[str] = None,
        agent_framework: Optional[str] = None,
    ) -> str:
        """Start agent run. Returns agent_run_id."""
        result = await self._request("POST", "/v1/agent/run/start", {
            "pipeline_id": self._pipeline_id,
            "agent_name": agent_name or self._agent_name,
            "agent_framework": agent_framework or self._agent_framework,
        })
        self._run_id = result["agent_run_id"]
        self._step_counter = 0
        return self._run_id

    async def protect(
        self,
        messages: Union[List[Dict], str],
        step_index: Optional[int] = None,
        mode: str = "tokenise",
    ) -> AsyncStepResult:
        """Protect messages before sending to LLM."""
        if not self._run_id:
            raise PrivaroError("Run not started. Use as async context manager.")

        if isinstance(messages, str):
            msgs = [{"role": "user", "content": messages, "step_type": "prompt"}]
        else:
            msgs = [{"role": m.get("role", "user"), "content": m.get("content", ""),
                     "step_type": m.get("step_type", "prompt")} for m in messages]

        idx = step_index if step_index is not None else self._step_counter
        result = await self._request("POST", "/v1/agent/protect", {
            "agent_run_id": self._run_id,
            "messages": msgs,
            "step_index": idx,
            "mode": mode,
        })
        self._step_counter += 1

        return AsyncStepResult(
            agent_run_id=self._run_id,
            step_index=result["step_index"],
            protected_messages=result["protected_messages"],
            total_pii_detected=result["total_pii_detected"],
            total_pii_masked=result["total_pii_masked"],
            risk_score=result["risk_score"],
            gdpr_compliant=result["gdpr_compliant"],
            audit_step_id=result.get("audit_step_id"),
        )

    async def reveal(self, text: str) -> str:
        """Detokenise text. Returns revealed string directly."""
        if not self._run_id:
            raise PrivaroError("Run not started.")
        result = await self._request("POST", "/v1/agent/reveal", {
            "agent_run_id": self._run_id,
            "text": text,
        })
        return result["revealed_text"]

    async def end(self, status: str = "completed") -> dict:
        """Close the run."""
        if not self._run_id:
            return {}
        return await self._request("POST", "/v1/agent/run/end", {
            "agent_run_id": self._run_id,
            "status": status,
        })

    @property
    def run_id(self) -> Optional[str]:
        return self._run_id


class CrewAIPrivaroTool:
    """
    CrewAI-compatible tool wrapper that protects inputs before processing.

    Usage:
        from privaro.async_client import CrewAIPrivaroTool

        class MyAnalysisTool(CrewAIPrivaroTool):
            name = "Contract Analyser"
            description = "Analyses contracts for compliance issues"

            async def _execute(self, protected_input: str, run: AsyncAgentRun) -> str:
                # protected_input has PII already tokenised
                return await your_llm.acomplete(protected_input)
    """

    name: str = "Privaro Protected Tool"
    description: str = "Tool with built-in PII protection"

    def __init__(self, api_key: Optional[str] = None, pipeline_id: Optional[str] = None):
        self._api_key = api_key
        self._pipeline_id = pipeline_id

    async def _run_protected(self, input_text: str) -> str:
        async with AsyncAgentRun(
            api_key=self._api_key,
            pipeline_id=self._pipeline_id,
            agent_framework="crewai",
        ) as run:
            step = await run.protect(input_text)
            result = await self._execute(step.first_content, run)
            return await run.reveal(result) if result else result

    async def _execute(self, protected_input: str, run: AsyncAgentRun) -> str:
        """Override this method with your tool logic."""
        raise NotImplementedError("Implement _execute() in your CrewAI tool subclass.")
