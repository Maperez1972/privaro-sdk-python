"""
Privaro SDK — Tests
Run: pytest tests/
"""
import pytest
from unittest.mock import patch, MagicMock
import json

import privaro
from privaro.client import PrivaroClient
from privaro.models import ProtectResult, Detection
from privaro.exceptions import AuthError, PipelineNotFoundError, PrivaroError


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
