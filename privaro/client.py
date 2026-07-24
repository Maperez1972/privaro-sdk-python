"""
Privaro SDK — HTTP Client
"""
import json
from typing import Optional, List, Dict, Iterator, Any
from .models import ProtectResult, Detection
from .exceptions import (
    PrivaroError, AuthError, PipelineNotFoundError,
    PolicyBlockError, RateLimitError, ProxyUnavailableError,
)


class PrivaroClient:
    """
    Privaro API client. Use privaro.init() for the module-level default,
    or instantiate directly for multiple pipelines.

    Example:
        client = PrivaroClient(
            api_key="prvr_xxx",
            pipeline_id="uuid",
        )
        result = client.protect("María García, DNI 34521789X")
    """

    DEFAULT_BASE_URL = "https://api.privaro.ai/v1"

    def __init__(
        self,
        api_key: str,
        pipeline_id: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 10.0,
    ):
        if not api_key or not api_key.startswith("prvr_"):
            raise AuthError("Invalid API key format. Keys must start with 'prvr_'.")
        if not pipeline_id:
            raise PrivaroError("pipeline_id is required.")

        self.api_key = api_key
        self.pipeline_id = pipeline_id
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _headers(self, idempotency_key: Optional[str] = None) -> dict:
        headers = {
            "Content-Type": "application/json",
            "X-Privaro-Key": self.api_key,
        }
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        return headers

    def _request(
        self, method: str, path: str, payload: dict,
        idempotency_key: Optional[str] = None,
    ) -> dict:
        """Execute HTTP request. Uses urllib (no dependencies)."""
        import urllib.request
        import urllib.error

        url = f"{self.base_url}{path}"
        data = json.dumps(payload).encode("utf-8")

        req = urllib.request.Request(
            url, data=data, headers=self._headers(idempotency_key), method=method
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body = {}
            try:
                body = json.loads(e.read().decode("utf-8"))
            except Exception:
                pass

            if e.code == 401:
                raise AuthError("Invalid API key or unauthorized access.")
            if e.code == 403:
                raise AuthError("Access denied — check API key permissions.")
            if e.code == 404:
                raise PipelineNotFoundError(
                    f"Pipeline '{self.pipeline_id}' not found or not accessible."
                )
            if e.code == 429:
                raise RateLimitError("Rate limit exceeded. Slow down requests.")
            if e.code == 500:
                detail = body.get("detail", {})
                if isinstance(detail, dict) and detail.get("error") == "request_blocked":
                    raise PolicyBlockError("Request blocked by privacy policy.", [])
                raise PrivaroError(f"Proxy API error: {body}")
            raise PrivaroError(f"HTTP {e.code}: {body}")

        except urllib.error.URLError as e:
            raise ProxyUnavailableError(
                f"Cannot reach Privaro proxy at {self.base_url}. "
                f"Check your network or proxy URL. ({e.reason})"
            )

    def _parse_result(self, raw: dict, original: str) -> ProtectResult:
        """Parse API response into ProtectResult."""
        detections = [
            Detection(
                type=d.get("type", ""),
                severity=d.get("severity", "low"),
                action=d.get("action", "detected"),
                token=d.get("token"),
                confidence=d.get("confidence", 1.0),
                detector=d.get("detector", "regex"),
                start=d.get("start"),
                end=d.get("end"),
            )
            for d in raw.get("detections", [])
        ]

        stats = raw.get("stats", {})

        return ProtectResult(
            protected=raw.get("protected_prompt", original),
            original=original,
            request_id=raw.get("request_id", ""),
            audit_log_id=raw.get("audit_log_id"),
            detections=detections,
            total_detected=stats.get("total_detected", 0),
            total_masked=stats.get("total_masked", 0),
            leaked=stats.get("leaked", 0),
            coverage_pct=stats.get("coverage_pct", 100.0),
            risk_score=stats.get("risk_score"),
            gdpr_compliant=raw.get("gdpr_compliant", True),
            processing_ms=stats.get("processing_ms", 0),
        )

    def protect(
        self,
        prompt: str,
        mode: str = "tokenise",
        reversible: bool = True,
        agent_mode: bool = False,
        include_detections: bool = True,
        conversation_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> ProtectResult:
        """
        Detect and mask PII in a prompt. Writes to audit log.

        Args:
            prompt:             Text to protect
            mode:               tokenise | anonymise | block
            reversible:         Store reversible tokens in vault
            agent_mode:         Stricter policies for agent pipelines
            include_detections: Include per-entity details in response
            conversation_id:    Group tokens within a conversation for
                                 consistent replacement across turns
            idempotency_key:    Safe-retry key — a repeated call with the
                                 same key returns the exact same response
                                 without re-billing

        Returns:
            ProtectResult — use .protected to send to your LLM

        Raises:
            AuthError, PipelineNotFoundError, PolicyBlockError, PrivaroError
        """
        if not prompt or not prompt.strip():
            return ProtectResult(
                protected="", original="", request_id="",
                audit_log_id=None, gdpr_compliant=True,
            )

        payload = {
            "pipeline_id": self.pipeline_id,
            "prompt": prompt,
            "options": {
                "mode": mode,
                "reversible": reversible,
                "agent_mode": agent_mode,
                "include_detections": include_detections,
            },
        }
        if conversation_id:
            payload["conversation_id"] = conversation_id

        raw = self._request("POST", "/proxy/protect", payload, idempotency_key)

        return self._parse_result(raw, original=prompt)

    def detect(self, prompt: str) -> ProtectResult:
        """
        Detect PII without masking. Analysis mode only — no audit log written.

        Returns:
            ProtectResult with detections populated, .protected == original
        """
        if not prompt or not prompt.strip():
            return ProtectResult(
                protected=prompt, original=prompt, request_id="",
                audit_log_id=None, gdpr_compliant=True,
            )

        raw = self._request("POST", "/proxy/detect", {
            "pipeline_id": self.pipeline_id,
            "prompt": prompt,
        })

        # detect returns detections list directly
        result = self._parse_result(
            {**raw, "protected_prompt": prompt, "gdpr_compliant": True},
            original=prompt,
        )
        result.protected = prompt  # detect doesn't mask
        return result

    def relay(
        self,
        messages: List[Dict[str, str]],
        mode: str = "tokenise",
        detokenise_response: bool = True,
        include_detections: bool = True,
        max_tokens: int = 2048,
        temperature: float = 0.7,
        system_prompt: Optional[str] = None,
        conversation_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Full-cycle privacy relay: protect messages, call the configured LLM
        (your own key, set in /app/admin/providers), de-tokenise the
        response, return everything in one call (no streaming).

        Args:
            messages: [{"role": "user"|"assistant"|"system", "content": "..."}]

        Returns:
            dict with keys: request_id, provider, model, response
            (already de-tokenised when detokenise_response=True),
            response_raw, pii_detected, pii_masked, risk_score,
            gdpr_compliant, audit_log_id, tokens_replaced, usage,
            processing_ms.
        """
        payload = {
            "pipeline_id": self.pipeline_id,
            "messages": messages,
            "options": {
                "mode": mode,
                "detokenise_response": detokenise_response,
                "include_detections": include_detections,
                "max_tokens": max_tokens,
                "temperature": temperature,
            },
        }
        if system_prompt:
            payload["options"]["system_prompt"] = system_prompt
        if conversation_id:
            payload["conversation_id"] = conversation_id

        return self._request("POST", "/relay/complete", payload, idempotency_key)

    def relay_stream(
        self,
        messages: List[Dict[str, str]],
        mode: str = "tokenise",
        detokenise_response: bool = True,
        include_detections: bool = True,
        max_tokens: int = 2048,
        temperature: float = 0.7,
        system_prompt: Optional[str] = None,
        conversation_id: Optional[str] = None,
    ) -> Iterator[str]:
        """
        Full-cycle privacy relay, streamed as the LLM generates it.
        Yields already de-tokenised text deltas — never emits a raw
        token, safe to render directly in a chat UI.

        Supported for streaming today: OpenAI, Azure OpenAI, Anthropic.
        Other providers raise PrivaroError — use relay() (non-streaming)
        for those instead.

        Note: idempotency_key is not supported here (replaying a completed
        stream doesn't have the same "just resend the result" semantics
        as a short synchronous response) — use relay() if you need
        idempotent retries.

        Example:
            for delta in client.relay_stream(messages):
                print(delta, end="", flush=True)
        """
        import urllib.request
        import urllib.error

        payload: Dict[str, Any] = {
            "pipeline_id": self.pipeline_id,
            "messages": messages,
            "options": {
                "mode": mode,
                "detokenise_response": detokenise_response,
                "include_detections": include_detections,
                "max_tokens": max_tokens,
                "temperature": temperature,
            },
        }
        if system_prompt:
            payload["options"]["system_prompt"] = system_prompt
        if conversation_id:
            payload["conversation_id"] = conversation_id

        url = f"{self.base_url}/relay/stream"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=self._headers(), method="POST")

        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout)
        except urllib.error.HTTPError as e:
            body = {}
            try:
                body = json.loads(e.read().decode("utf-8"))
            except Exception:
                pass
            if e.code == 401 or e.code == 403:
                raise AuthError("Invalid API key or unauthorized access.")
            if e.code == 404:
                raise PipelineNotFoundError(
                    f"Pipeline '{self.pipeline_id}' not found or not accessible."
                )
            if e.code == 429:
                raise RateLimitError("Rate limit exceeded. Slow down requests.")
            raise PrivaroError(f"HTTP {e.code}: {body}")
        except urllib.error.URLError as e:
            raise ProxyUnavailableError(
                f"Cannot reach Privaro proxy at {self.base_url}. "
                f"Check your network or proxy URL. ({e.reason})"
            )

        buffer = ""
        try:
            with resp:
                for raw_bytes in resp:
                    buffer += raw_bytes.decode("utf-8", errors="ignore")
                    while "\n\n" in buffer:
                        line, buffer = buffer.split("\n\n", 1)
                        line = line.strip()
                        if not line.startswith("data:"):
                            continue
                        raw = line[len("data:"):].strip()
                        if not raw or raw == "[DONE]":
                            continue
                        try:
                            event = json.loads(raw)
                        except json.JSONDecodeError:
                            continue
                        if event.get("error"):
                            raise PrivaroError(f"LLM provider error: {event['error']}")
                        delta = event.get("delta")
                        if delta:
                            yield delta
        finally:
            resp.close()

    def health(self) -> dict:
        """Check proxy health. Returns status dict."""
        return self._request("GET", "/health", {})

    def __repr__(self) -> str:
        return (
            f"PrivaroClient(pipeline={self.pipeline_id[:8]}..., "
            f"url={self.base_url})"
        )
