"""
Privaro SDK — Tests
Run: pytest tests/
"""
import pytest
from unittest.mock import patch, MagicMock
import json

import privaro
from privaro.client import PrivaroClient
from privaro.models import ProtectResult, Detection, ProtectOutputResult
from privaro.exceptions import (
    AuthError, PipelineNotFoundError, PrivaroError, OutputScanningDisabledError,
)


MOCK_PIPELINE_ID = "c93aed87-b440-4de0-bb21-54a938e475f2"
MOCK_API_KEY = "prvr_test_key_12345678901234567890"

MOCK_PROTECT_RESPONSE = {
    "request_id": "req_abc123",
    "protected_prompt": "Paciente: [NM-0001], DNI [ID-0001]",
    "detections": [
        {
            "type": "full_name",
            "severity": "low",
            "action": "tokenised",
            "token": "[NM-0001]",
            "confidence": 0.75,
            "detector": "presidio",
            "start": 10,
            "end": 22,
        },
        {
            "type": "dni",
            "severity": "critical",
            "action": "tokenised",
            "token": "[ID-0001]",
            "confidence": 0.95,
            "detector": "regex",
            "start": 29,
            "end": 38,
        },
    ],
    "stats": {
        "total_detected": 2,
        "total_masked": 2,
        "leaked": 0,
        "coverage_pct": 100.0,
        "processing_ms": 47,
        "risk_score": 0.847,
    },
    "audit_log_id": "uuid-audit-log",
    "gdpr_compliant": True,
}


class TestPrivaroInit:
    def test_init_sets_default_client(self):
        client = privaro.init(api_key=MOCK_API_KEY, pipeline_id=MOCK_PIPELINE_ID)
        assert isinstance(client, PrivaroClient)
        assert privaro._default_client is client

    def test_invalid_api_key_raises(self):
        with pytest.raises(AuthError):
            PrivaroClient(api_key="invalid_key", pipeline_id=MOCK_PIPELINE_ID)

    def test_missing_pipeline_raises(self):
        with pytest.raises(PrivaroError):
            PrivaroClient(api_key=MOCK_API_KEY, pipeline_id="")

    def test_protect_without_init_raises(self):
        privaro._default_client = None
        with pytest.raises(PrivaroError, match="not initialized"):
            privaro.protect("test")


class TestProtectResult:
    def setup_method(self):
        self.client = PrivaroClient(
            api_key=MOCK_API_KEY,
            pipeline_id=MOCK_PIPELINE_ID,
        )

    def _mock_request(self, response: dict):
        self.client._request = MagicMock(return_value=response)

    def test_protect_returns_result(self):
        self._mock_request(MOCK_PROTECT_RESPONSE)
        result = self.client.protect("Paciente: María García, DNI 34521789X")

        assert isinstance(result, ProtectResult)
        assert result.protected == "Paciente: [NM-0001], DNI [ID-0001]"
        assert result.total_detected == 2
        assert result.total_masked == 2
        assert result.leaked == 0
        assert result.gdpr_compliant is True
        assert result.risk_score == pytest.approx(0.847)
        assert result.risk_level == "high"
        assert result.is_safe is True

    def test_detections_parsed(self):
        self._mock_request(MOCK_PROTECT_RESPONSE)
        result = self.client.protect("Paciente: María García, DNI 34521789X")

        assert len(result.detections) == 2
        dni = next(d for d in result.detections if d.type == "dni")
        assert dni.severity == "critical"
        assert dni.token == "[ID-0001]"
        assert dni.detector == "regex"
        assert dni.is_high_risk is True

        name = next(d for d in result.detections if d.type == "full_name")
        assert name.detector == "presidio"
        assert name.confidence == 0.75

    def test_empty_prompt_returns_early(self):
        result = self.client.protect("")
        assert result.protected == ""
        assert result.total_detected == 0

    def test_clean_prompt_no_detections(self):
        self._mock_request({
            "request_id": "req_clean",
            "protected_prompt": "Hello world",
            "detections": [],
            "stats": {"total_detected": 0, "total_masked": 0, "leaked": 0,
                      "coverage_pct": 100.0, "processing_ms": 12, "risk_score": 0.0},
            "audit_log_id": None,
            "gdpr_compliant": True,
        })
        result = self.client.protect("Hello world")
        assert result.has_pii is False
        assert result.risk_level == "low"


class TestProtectResultProperties:
    def test_risk_level_high(self):
        r = ProtectResult(protected="", original="", request_id="",
                          audit_log_id=None, risk_score=0.85)
        assert r.risk_level == "high"

    def test_risk_level_medium(self):
        r = ProtectResult(protected="", original="", request_id="",
                          audit_log_id=None, risk_score=0.5)
        assert r.risk_level == "medium"

    def test_risk_level_low(self):
        r = ProtectResult(protected="", original="", request_id="",
                          audit_log_id=None, risk_score=0.2)
        assert r.risk_level == "low"

    def test_summary_format(self):
        r = ProtectResult(
            protected="[ID-0001]", original="test", request_id="req_1",
            audit_log_id="uuid", total_detected=1, total_masked=1,
            risk_score=0.9, gdpr_compliant=True, processing_ms=50,
        )
        summary = r.summary()
        assert "1 entities detected" in summary
        assert "high" in summary
        assert "50ms" in summary


class TestRelay:
    def setup_method(self):
        self.client = PrivaroClient(api_key=MOCK_API_KEY, pipeline_id=MOCK_PIPELINE_ID)

    def test_relay_calls_complete_endpoint(self):
        self.client._request = MagicMock(return_value={
            "request_id": "relay_abc", "provider": "openai", "model": "gpt-4o",
            "response": "Claro, Juan Pérez, su cita es el...",
            "response_raw": None, "pii_detected": 1, "pii_masked": 1,
            "risk_score": 0.3, "gdpr_compliant": True, "audit_log_id": "uuid",
            "tokens_replaced": 1, "usage": {}, "processing_ms": 500,
        })
        result = self.client.relay([{"role": "user", "content": "hola"}])
        assert result["response"] == "Claro, Juan Pérez, su cita es el..."
        # Confirm it called /relay/complete, not /proxy/protect
        call_args = self.client._request.call_args
        assert call_args[0][1] == "/relay/complete"

    def test_relay_passes_conversation_id_and_idempotency_key(self):
        self.client._request = MagicMock(return_value={"response": "ok"})
        self.client.relay(
            [{"role": "user", "content": "hola"}],
            conversation_id="conv-123",
            idempotency_key="idem-456",
        )
        call_args = self.client._request.call_args
        payload = call_args[0][2]
        assert payload["conversation_id"] == "conv-123"
        assert call_args[0][3] == "idem-456"  # 4th positional arg is idempotency_key


class FakeStreamResponse:
    """Mimics an http.client.HTTPResponse enough for relay_stream()'s
    line-by-line iteration and context-manager usage."""

    def __init__(self, chunks: list[bytes]):
        self._chunks = chunks

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def close(self):
        pass

    def __iter__(self):
        return iter(self._chunks)


class TestRelayStream:
    def setup_method(self):
        self.client = PrivaroClient(api_key=MOCK_API_KEY, pipeline_id=MOCK_PIPELINE_ID)

    def test_yields_detokenised_deltas(self):
        chunks = [
            b'data: {"delta": "Claro, "}\n\n',
            b'data: {"delta": "Juan P\xc3\xa9rez"}\n\n',
            b'data: {"delta": ", su cita es el..."}\n\n',
            b"data: [DONE]\n\n",
        ]
        with patch("urllib.request.urlopen", return_value=FakeStreamResponse(chunks)):
            deltas = list(self.client.relay_stream([{"role": "user", "content": "hola"}]))
        assert "".join(deltas) == "Claro, Juan Pérez, su cita es el..."

    def test_handles_event_split_across_chunks(self):
        # The exact same logical event, but the chunk boundary falls
        # mid-JSON — must still parse correctly once buffered.
        chunks = [
            b'data: {"del',
            b'ta": "hola mundo"}\n\ndata: [DONE]\n\n',
        ]
        with patch("urllib.request.urlopen", return_value=FakeStreamResponse(chunks)):
            deltas = list(self.client.relay_stream([{"role": "user", "content": "hola"}]))
        assert "".join(deltas) == "hola mundo"

    def test_raises_on_provider_error(self):
        chunks = [
            b'data: {"error": "OpenAI error 401: invalid key", "provider": "openai"}\n\n',
            b"data: [DONE]\n\n",
        ]
        with patch("urllib.request.urlopen", return_value=FakeStreamResponse(chunks)):
            with pytest.raises(PrivaroError):
                list(self.client.relay_stream([{"role": "user", "content": "hola"}]))


MOCK_PROTECT_OUTPUT_RESPONSE = {
    "request_id": "req_out_1",
    "protected_response": "Según nuestros registros, [NM-0001] tiene DNI [ID-0001].",
    "detections": [
        {
            "type": "dni", "severity": "critical", "action": "tokenised",
            "token": "[ID-0001]", "confidence": 0.95, "detector": "regex",
            "start": 45, "end": 54,
        },
    ],
    "stats": {
        "total_detected": 1, "total_masked": 1, "leaked": 0,
        "coverage_pct": 100.0, "processing_ms": 33, "risk_score": 0.7,
    },
    "audit_log_id": "uuid-output-audit-log",
    "gdpr_compliant": True,
    "scan_mode": "shadow",
    "response_modified": True,
}


class TestProtectOutput:
    def setup_method(self):
        self.client = PrivaroClient(api_key=MOCK_API_KEY, pipeline_id=MOCK_PIPELINE_ID)

    def _mock_request(self, response: dict):
        self.client._request = MagicMock(return_value=response)

    def test_protect_output_returns_result(self):
        self._mock_request(MOCK_PROTECT_OUTPUT_RESPONSE)
        result = self.client.protect_output(
            "Según nuestros registros, Juan Perez tiene DNI 12345678Z.",
            conversation_id="conv-1",
        )

        assert isinstance(result, ProtectOutputResult)
        assert result.protected == MOCK_PROTECT_OUTPUT_RESPONSE["protected_response"]
        assert result.total_detected == 1
        assert result.total_masked == 1
        assert result.leaked == 0
        assert result.scan_mode == "shadow"
        assert result.response_modified is True
        assert result.gdpr_compliant is True
        assert result.risk_score == pytest.approx(0.7)

    def test_protect_output_calls_correct_endpoint(self):
        self._mock_request(MOCK_PROTECT_OUTPUT_RESPONSE)
        self.client.protect_output("respuesta del LLM", conversation_id="conv-1")
        call_args = self.client._request.call_args
        assert call_args[0][1] == "/proxy/protect-output"
        payload = call_args[0][2]
        assert payload["response_text"] == "respuesta del LLM"
        assert payload["conversation_id"] == "conv-1"

    def test_protect_output_detections_parsed(self):
        self._mock_request(MOCK_PROTECT_OUTPUT_RESPONSE)
        result = self.client.protect_output("texto", conversation_id="conv-1")
        assert len(result.detections) == 1
        dni = result.detections[0]
        assert dni.type == "dni"
        assert dni.token == "[ID-0001]"
        assert dni.is_high_risk is True

    def test_protect_output_empty_text_returns_early(self):
        result = self.client.protect_output("", conversation_id="conv-1")
        assert result.protected == ""
        assert result.total_detected == 0

    def test_protect_output_raises_when_scanning_disabled(self):
        import json as _json
        import urllib.error

        http_error = urllib.error.HTTPError(
            url="https://api.privaro.ai/v1/proxy/protect-output",
            code=403,
            msg="Forbidden",
            hdrs=None,
            fp=MagicMock(read=lambda: _json.dumps({
                "detail": {
                    "error": "output_scanning_disabled",
                    "message": "This pipeline has not enabled output-direction PII scanning.",
                }
            }).encode()),
        )

        def raise_it(*a, **kw):
            raise http_error

        with patch("urllib.request.urlopen", side_effect=raise_it):
            with pytest.raises(OutputScanningDisabledError, match="output-direction"):
                self.client.protect_output("texto con PII", conversation_id="conv-1")

    def test_protect_output_enforce_mode_reflected(self):
        enforce_response = dict(MOCK_PROTECT_OUTPUT_RESPONSE, scan_mode="enforce")
        self._mock_request(enforce_response)
        result = self.client.protect_output("texto", conversation_id="conv-1")
        assert result.scan_mode == "enforce"


class TestAgentRunAuthHeader:
    """Regression test for a real bug: AgentRun sent Authorization: Bearer,
    but the proxy only ever checks X-Privaro-Key — every AgentRun call has
    been failing with 401 since this SDK's first release, until fixed
    2026-07-24."""

    def test_sync_agent_run_uses_x_privaro_key_header(self):
        from privaro.agent import AgentRun

        captured = {}

        def fake_urlopen(req, timeout=None):
            captured["headers"] = dict(req.header_items())
            response = MagicMock()
            response.read.return_value = json.dumps({
                "agent_run_id": "run-1", "pipeline_id": MOCK_PIPELINE_ID, "status": "running",
            }).encode()
            response.__enter__ = lambda s: response
            response.__exit__ = lambda s, *a: None
            return response

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            run = AgentRun(api_key=MOCK_API_KEY, pipeline_id=MOCK_PIPELINE_ID)
            run.start()

        # Header names are capitalized by urllib (X-privaro-key), so compare
        # case-insensitively rather than asserting exact casing.
        header_names = {k.lower(): v for k, v in captured["headers"].items()}
        assert "x-privaro-key" in header_names
        assert header_names["x-privaro-key"] == MOCK_API_KEY
        assert "authorization" not in header_names
