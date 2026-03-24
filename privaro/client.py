"""
Privaro SDK — HTTP Client
"""
import json
from typing import Optional
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

    DEFAULT_BASE_URL = "https://privaro-proxy-production.up.railway.app/v1"

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

    def _headers(self) -> dict:
        return {
            "Content-Type": "application/json",
            "X-Privaro-Key": self.api_key,
        }

    def _request(self, method: str, path: str, payload: dict) -> dict:
        """Execute HTTP request. Uses urllib (no dependencies)."""
        import urllib.request
        import urllib.error

        url = f"{self.base_url}{path}"
        data = json.dumps(payload).encode("utf-8")

        req = urllib.request.Request(url, data=data, headers=self._headers(), method=method)

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
    ) -> ProtectResult:
        """
        Detect and mask PII in a prompt. Writes to audit log.

        Args:
            prompt:             Text to protect
            mode:               tokenise | anonymise | block
            reversible:         Store reversible tokens in vault
            agent_mode:         Stricter policies for agent pipelines
            include_detections: Include per-entity details in response

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

        raw = self._request("POST", "/proxy/protect", {
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

    def health(self) -> dict:
        """Check proxy health. Returns status dict."""
        return self._request("GET", "/health", {})

    def __repr__(self) -> str:
        return (
            f"PrivaroClient(pipeline={self.pipeline_id[:8]}..., "
            f"url={self.base_url})"
        )
