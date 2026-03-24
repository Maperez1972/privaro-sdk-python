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
