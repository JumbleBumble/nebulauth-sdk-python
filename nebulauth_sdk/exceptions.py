class NebulAuthError(Exception):
    """Base SDK error."""


class NebulAuthConfigError(NebulAuthError):
    """Raised when required SDK configuration is missing or invalid."""


class NebulAuthRequestError(NebulAuthError):
    """Raised when an HTTP request fails before receiving a valid API response."""
