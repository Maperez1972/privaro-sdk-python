"""
Privaro SDK — Exceptions
"""


class PrivaroError(Exception):
    """Base exception for all Privaro SDK errors."""
    pass


class AuthError(PrivaroError):
    """Invalid or missing API key."""
    pass


class PipelineNotFoundError(PrivaroError):
    """Pipeline ID not found or not accessible."""
    pass


class PolicyBlockError(PrivaroError):
    """Request was blocked by a policy rule."""
    def __init__(self, message: str, detections: list = None):
        super().__init__(message)
        self.detections = detections or []


class RateLimitError(PrivaroError):
    """API rate limit exceeded."""
    pass


class ProxyUnavailableError(PrivaroError):
    """Proxy API is unreachable."""
    pass


class OutputScanningDisabledError(PrivaroError):
    """
    Raised by protect_output() when the pipeline hasn't opted into
    output-direction PII scanning (pipeline.output_scanning_enabled=false).

    Enable it in the dashboard: Pipelines → Settings → Output scanning.
    This is a deliberate hard failure (not a silent passthrough) — a
    caller invoking protect_output() explicitly wants their LLM's
    response scanned, so a disabled pipeline must not pretend to have
    done that.
    """
    pass
