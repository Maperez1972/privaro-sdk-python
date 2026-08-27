"""
Privaro SDK — Data models
"""
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List


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

    # Context Optimization — populated only when optimize_context=True was
    # passed to protect(). Added 2026-07-30 after a full integration audit
    # found the API already returns this field but the SDK silently
    # dropped it during response parsing.
    compression_stats: Optional[Dict[str, Any]] = None

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


@dataclass
class ProtectOutputResult:
    """
    Result of a protect_output() call — scans an LLM RESPONSE for PII
    (as opposed to ProtectResult, which scans a prompt going INTO the
    LLM). Added 2026-08 for output-direction PII detection: customers
    who call protect() themselves, send the protected prompt to their
    OWN LLM, and get a raw response back had zero Privaro visibility
    into that response until now.
    """

    # Core output
    protected: str                          # Response text with PII replaced by tokens
    original: str                           # Original LLM response text (kept locally)
    request_id: str
    audit_log_id: Optional[str]

    # PII summary
    detections: list[Detection] = field(default_factory=list)
    total_detected: int = 0
    total_masked: int = 0
    leaked: int = 0
    coverage_pct: float = 100.0

    risk_score: Optional[float] = None
    gdpr_compliant: bool = True

    processing_ms: int = 0

    # "shadow" (informational — detections resolved but never masked
    # server-side beyond what this call itself did) or "enforce"
    # (pipeline.output_scanning_mode) — mirrors the pipeline's dashboard
    # setting at the time of the call.
    scan_mode: str = "shadow"

    # True if the returned .protected text differs from .original —
    # i.e. this call actually masked/tokenised something.
    response_modified: bool = False

    @property
    def risk_level(self) -> str:
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
        return self.gdpr_compliant and self.leaked == 0

    def summary(self) -> str:
        return (
            f"[Privaro:output] {self.total_detected} entities detected, "
            f"{self.total_masked} masked, mode={self.scan_mode}, "
            f"risk={self.risk_level} ({self.risk_score or 0:.2f}), "
            f"gdpr={'✓' if self.gdpr_compliant else '✗'}, "
            f"{self.processing_ms}ms"
        )


# ── Privaro Ingest (Fase 1 del plan de RAG) ─────────────────────────────────

@dataclass
class DocumentChunk:
    """A single chunk of an already-protected document, ready to embed
    into a vector store. Chunk boundaries never split a Privaro token
    ([XX-0001]) — see the backend's chunker.py for the invariant this
    relies on."""
    index: int
    text: str
    char_start: int
    char_end: int


@dataclass
class ProtectDocumentResult:
    """
    Result of protect_document() — protects a WHOLE document (e.g.
    before indexing it into a vector store for RAG) rather than a
    single chat prompt.

    Large documents may be processed asynchronously server-side;
    protect_document() polls transparently until the result is ready,
    so this dataclass always represents a FINISHED result — never a
    partial/in-progress state.
    """
    request_id: str
    protected_document: str
    chunks: List[DocumentChunk]
    detections: List[Detection]
    stats: Dict[str, Any]
    job_id: Optional[str] = None  # set if the server processed this asynchronously

    @property
    def chunk_count(self) -> int:
        return len(self.chunks)

    def summary(self) -> str:
        return (
            f"[Privaro:ingest] {self.stats.get('total_detected', 0)} entities detected, "
            f"{self.chunk_count} chunks, {self.stats.get('char_count', 0)} chars, "
            f"{self.stats.get('processing_ms', 0)}ms"
        )


# ── Privaro Retrieval Guard (Fase 2 del plan de RAG) ────────────────────────

@dataclass
class RetrievalChunk:
    """A single chunk to protect before it enters an LLM's context — e.g.
    right after a vector store similarity search, before you stuff the
    results into a RAG prompt."""
    id: str
    text: str
    allowed_roles: Optional[List[str]] = None


@dataclass
class AllowedChunk:
    """A chunk that passed access control and was protected (tokenised)."""
    id: str
    protected_text: str
    detections_count: int
    from_cache: bool = False


@dataclass
class BlockedChunk:
    """A chunk withheld from the caller — either access-denied (its
    allowed_roles didn't include the requester's role) or a detection
    failure (see .reason: 'access_denied' | 'detector_error' |
    'detector_timeout'). Retrieval Guard fails CLOSED per chunk, unlike
    protect_document()'s whole-document fail-open — a batch of unrelated
    chunks must never let one chunk's detection failure silently pass
    raw, unprotected text into an LLM prompt just because its neighbours
    in the same batch succeeded."""
    id: str
    reason: str
    detail: Optional[str] = None


@dataclass
class ProtectRetrievalResult:
    """Result of protect_retrieval() — protects a BATCH of retrieved
    chunks (e.g. from a vector store similarity search) right before
    they enter an LLM's context, with optional per-chunk access control.
    """
    request_id: str
    allowed_chunks: List[AllowedChunk]
    blocked_chunks: List[BlockedChunk]
    stats: Dict[str, Any]

    def summary(self) -> str:
        return (
            f"[Privaro:retrieval] {len(self.allowed_chunks)} allowed, "
            f"{len(self.blocked_chunks)} blocked, "
            f"{self.stats.get('cache_hits', 0)} cache hits, "
            f"{self.stats.get('processing_ms', 0)}ms"
        )
