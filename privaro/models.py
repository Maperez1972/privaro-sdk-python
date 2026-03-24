"""
Privaro SDK — Data models
"""
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Detection:
    """A single PII entity detected in a prompt."""
    type: str               # dni | iban | email | full_name | phone | health_record ...
    severity: str           # critical | high | medium | low
    action: str             # tokenised | anonymised | blocked
    token: Optional[str]    # [ID-0001] if tokenised
    confidence: float       # 0.0–1.0
    detector: str           # regex | presidio
    start: Optional[int] = None
    end: Optional[int] = None

    @property
    def is_high_risk(self) -> bool:
        return self.severity in ("critical", "high")


@dataclass
class ProtectResult:
    """Result of a protect or detect call."""

    # Core output
    protected: str                          # Prompt with PII replaced by tokens
    original: str                           # Original prompt (stored locally, never sent back)
    request_id: str                         # req_xxxxxxxxxxxx
    audit_log_id: Optional[str]             # UUID of the audit log entry in Supabase

    # PII summary
    detections: list[Detection] = field(default_factory=list)
    total_detected: int = 0
    total_masked: int = 0
    leaked: int = 0
    coverage_pct: float = 100.0

    # Risk
    risk_score: Optional[float] = None      # 0.0–1.0 (None for detect-only)
    gdpr_compliant: bool = True

    # Performance
    processing_ms: int = 0

    @property
    def risk_level(self) -> str:
        """Human-readable risk level."""
        if self.risk_score is None:
            return "unknown"
        if self.risk_score >= 0.7:
            return "high"
        if self.risk_score >= 0.4:
            return "medium"
        return "low"

    @property
    def has_pii(self) -> bool:
        return self.total_detected > 0

    @property
    def is_safe(self) -> bool:
        """True if all PII was masked and no leaks detected."""
        return self.gdpr_compliant and self.leaked == 0

    def summary(self) -> str:
        """One-line summary for logging."""
        return (
            f"[Privaro] {self.total_detected} entities detected, "
            f"{self.total_masked} masked, "
            f"risk={self.risk_level} ({self.risk_score:.2f}), "
            f"gdpr={'✓' if self.gdpr_compliant else '✗'}, "
            f"{self.processing_ms}ms"
        )
