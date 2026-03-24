"""
privaro.agent — Agent middleware for LangChain, CrewAI, and direct use.

Usage (LangChain):
    from privaro import init
    from privaro.agent import PrivaroCallbackHandler

    init(api_key="prvr_...", pipeline_id="uuid")
    handler = PrivaroCallbackHandler()

    llm = ChatOpenAI(callbacks=[handler])
    agent = AgentExecutor(agent=agent, tools=tools, callbacks=[handler])

Usage (direct):
    from privaro.agent import AgentRun

    run = AgentRun(api_key="prvr_...", pipeline_id="uuid")
    run.start()
    protected = run.protect([{"role": "user", "content": "..."}])
    # ... call LLM with protected["protected_messages"]
    revealed = run.reveal(llm_response)
    run.end()
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, field

try:
    from privaro.client import _get_config, PrivaroError
except ImportError:
    # Standalone usage
    _get_config = None
    class PrivaroError(Exception):
        pass


@dataclass
class AgentRunResult:
    agent_run_id: str
    pipeline_id: str
    status: str = "running"


@dataclass
class StepResult:
    agent_run_id: str
    step_index: int
    protected_messages: List[Dict]
    total_pii_detected: int
    total_pii_masked: int
    risk_score: float
    gdpr_compliant: bool
    audit_step_id: Optional[str] = None


@dataclass
class RevealResult:
    agent_run_id: str
    revealed_text: str
    tokens_replaced: int


class AgentRun:
    """
    Context manager and direct API for agent governance.

    with AgentRun(api_key="...", pipeline_id="...") as run:
        protected = run.protect([{"role": "user", "content": "..."}])
        # call LLM...
        final_text = run.reveal(llm_response)
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        pipeline_id: Optional[str] = None,
        base_url: str = "https://privaro-proxy-production.up.railway.app",
        agent_name: Optional[str] = None,
        agent_framework: Optional[str] = None,
        external_run_id: Optional[str] = None,
    ):
        # Resolve config from init() if not provided directly
        if _get_config and (not api_key or not pipeline_id):
            cfg = _get_config()
            api_key = api_key or cfg.get("api_key")
            pipeline_id = pipeline_id or cfg.get("pipeline_id")
            base_url = base_url or cfg.get("base_url", base_url)

        if not api_key:
            raise PrivaroError("api_key is required. Call privaro.init() or pass api_key.")
        if not pipeline_id:
            raise PrivaroError("pipeline_id is required. Call privaro.init() or pass pipeline_id.")

        self._api_key = api_key
        self._pipeline_id = pipeline_id
        self._base_url = base_url.rstrip("/")
        self._agent_name = agent_name
        self._agent_framework = agent_framework
        self._external_run_id = external_run_id
        self._run_id: Optional[str] = None
        self._step_counter = 0

    def __enter__(self) -> "AgentRun":
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        status = "failed" if exc_type else "completed"
        try:
            self.end(status=status)
        except Exception:
            pass

    def _request(self, method: str, path: str, body: Optional[dict] = None) -> dict:
        url = f"{self._base_url}{path}"
        data = json.dumps(body).encode() if body else None
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            raise PrivaroError(f"Privaro API error {e.code}: {body}") from e

    def start(
        self,
        agent_name: Optional[str] = None,
        agent_framework: Optional[str] = None,
        external_run_id: Optional[str] = None,
    ) -> AgentRunResult:
        """Create a new agent run. Returns run details with agent_run_id."""
        result = self._request("POST", "/v1/agent/run/start", {
            "pipeline_id": self._pipeline_id,
            "agent_name": agent_name or self._agent_name,
            "agent_framework": agent_framework or self._agent_framework,
            "external_run_id": external_run_id or self._external_run_id,
        })
        self._run_id = result["agent_run_id"]
        self._step_counter = 0
        return AgentRunResult(
            agent_run_id=self._run_id,
            pipeline_id=result["pipeline_id"],
            status=result["status"],
        )

    def protect(
        self,
        messages: Union[List[Dict], str],
        step_index: Optional[int] = None,
        mode: str = "tokenise",
    ) -> StepResult:
        """
        Protect a step's messages before sending to LLM.

        messages can be:
          - List of dicts: [{"role": "user", "content": "..."}]
          - str: plain string (wrapped as user message)

        Returns StepResult with protected_messages ready to send to LLM.
        """
        if not self._run_id:
            raise PrivaroError("Agent run not started. Call start() first.")

        # Normalise input
        if isinstance(messages, str):
            msgs = [{"role": "user", "content": messages, "step_type": "prompt"}]
        else:
            msgs = []
            for m in messages:
                msgs.append({
                    "role": m.get("role", "user"),
                    "content": m.get("content", ""),
                    "step_type": m.get("step_type", "prompt"),
                    "tool_name": m.get("tool_name"),
                })

        idx = step_index if step_index is not None else self._step_counter
        result = self._request("POST", "/v1/agent/protect", {
            "agent_run_id": self._run_id,
            "messages": msgs,
            "step_index": idx,
            "mode": mode,
        })
        self._step_counter += 1

        return StepResult(
            agent_run_id=self._run_id,
            step_index=result["step_index"],
            protected_messages=result["protected_messages"],
            total_pii_detected=result["total_pii_detected"],
            total_pii_masked=result["total_pii_masked"],
            risk_score=result["risk_score"],
            gdpr_compliant=result["gdpr_compliant"],
            audit_step_id=result.get("audit_step_id"),
        )

    def reveal(self, text: str) -> RevealResult:
        """
        Detokenise text using this run's token map.
        Call after receiving final LLM response to restore original values.
        """
        if not self._run_id:
            raise PrivaroError("Agent run not started. Call start() first.")

        result = self._request("POST", "/v1/agent/reveal", {
            "agent_run_id": self._run_id,
            "text": text,
        })
        return RevealResult(
            agent_run_id=self._run_id,
            revealed_text=result["revealed_text"],
            tokens_replaced=result["tokens_replaced"],
        )

    def end(self, status: str = "completed") -> dict:
        """Close the run and finalise audit counters."""
        if not self._run_id:
            return {}
        result = self._request("POST", "/v1/agent/run/end", {
            "agent_run_id": self._run_id,
            "status": status,
        })
        return result

    @property
    def run_id(self) -> Optional[str]:
        return self._run_id


class PrivaroCallbackHandler:
    """
    LangChain-compatible callback handler that wraps agent interactions with Privaro.

    Intercepts on_llm_start to protect prompts and on_tool_end to protect tool outputs.
    Does NOT require LangChain to be installed — uses duck-typing interface.

    Usage:
        handler = PrivaroCallbackHandler()
        llm = ChatOpenAI(callbacks=[handler])
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        pipeline_id: Optional[str] = None,
        agent_name: str = "langchain-agent",
        auto_start: bool = True,
    ):
        self._agent = AgentRun(
            api_key=api_key,
            pipeline_id=pipeline_id,
            agent_name=agent_name,
            agent_framework="langchain",
        )
        self._auto_start = auto_start
        self._started = False

    def on_chain_start(self, serialized: dict, inputs: dict, **kwargs) -> None:
        """Called when a chain starts — begin agent run."""
        if self._auto_start and not self._started:
            self._agent.start()
            self._started = True

    def on_llm_start(
        self, serialized: dict, prompts: List[str], **kwargs
    ) -> None:
        """Called before LLM call — protect prompts in-place."""
        if not self._started:
            self._agent.start()
            self._started = True

        for i, prompt in enumerate(prompts):
            try:
                result = self._agent.protect(prompt)
                if result.protected_messages:
                    prompts[i] = result.protected_messages[0]["content"]
            except PrivaroError as e:
                print(f"[Privaro] Warning: protect failed for prompt {i}: {e}")

    def on_tool_end(self, output: str, **kwargs) -> None:
        """Called after tool execution — protect tool output before passing to LLM."""
        if not self._started:
            return
        try:
            result = self._agent.protect([{
                "role": "tool",
                "content": output,
                "step_type": "tool_output",
            }])
            if result.protected_messages:
                # Note: LangChain doesn't support in-place mutation of tool output
                # here — this logs the protection event. For full interception,
                # use AgentRun directly in a custom agent executor.
                pass
        except PrivaroError as e:
            print(f"[Privaro] Warning: protect failed for tool output: {e}")

    def on_chain_end(self, outputs: dict, **kwargs) -> None:
        """Called when chain ends — close agent run."""
        if self._started:
            try:
                self._agent.end("completed")
                self._started = False
            except PrivaroError:
                pass

    def on_chain_error(self, error: Exception, **kwargs) -> None:
        """Called on chain error — close run with failed status."""
        if self._started:
            try:
                self._agent.end("failed")
                self._started = False
            except PrivaroError:
                pass
