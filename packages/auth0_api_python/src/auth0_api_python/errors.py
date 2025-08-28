"""
Custom exceptions for auth0-api-python SDK with HTTP response metadata
"""


class BaseAuthError(Exception):
    """Base class for all auth errors with HTTP response metadata."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message
        self.name = self.__class__.__name__
        self._headers = {}  # Will be set by ApiClient._prepare_error

    def get_status_code(self) -> int:
        """Return the HTTP status code for this error."""
        raise NotImplementedError("Subclasses must implement get_status_code()")

    def get_error_code(self) -> str:
        """Return the OAuth/DPoP error code."""
        raise NotImplementedError("Subclasses must implement get_error_code()")

    def get_error_description(self) -> str:
        """Return the error description."""
        return self.message

    def get_headers(self) -> dict[str, str]:
        """Return HTTP headers (including WWW-Authenticate if set)."""
        return self._headers


class MissingRequiredArgumentError(BaseAuthError):
    """Error raised when a required argument is missing."""

    def __init__(self, argument: str, message: str = None):
        if message:
            super().__init__(message)
        else:
            super().__init__(f"The argument '{argument}' is required but was not provided.")
        self.argument = argument

    def get_status_code(self) -> int:
        return 400

    def get_error_code(self) -> str:
        return "invalid_request"


class VerifyAccessTokenError(BaseAuthError):
    """Error raised when verifying the access token fails."""

    def get_status_code(self) -> int:
        return 401

    def get_error_code(self) -> str:
        return "invalid_token"


class InvalidAuthSchemeError(BaseAuthError):
    """Error raised when the provided authentication scheme is unsupported."""

    def __init__(self, message: str):
        super().__init__(message)
        if ":" in message and "'" in message:
            self.scheme = message.split("'")[1]
        else:
            self.scheme = None

    def get_status_code(self) -> int:
        return 400

    def get_error_code(self) -> str:
        return "invalid_request"


class InvalidDpopProofError(BaseAuthError):
    """Error raised when validating a DPoP proof fails."""

    def get_status_code(self) -> int:
        return 400

    def get_error_code(self) -> str:
        return "invalid_dpop_proof"


class MissingAuthorizationError(BaseAuthError):
    """Authorization header is missing, empty, or malformed."""

    def __init__(self):
        super().__init__("")

    def get_status_code(self) -> int:
        return 400

    def get_error_code(self) -> str:
        return "invalid_request"


class GetTokenForConnectionError(Exception):
    """Error raised when getting a token for a connection fails."""
    code = "get_token_for_connection_error"

    def __init__(self, message: str):
        super().__init__(message)
        self.name = self.__class__.__name__


class ApiError(Exception):
    """
    Error raised when an API request to Auth0 fails.
    Contains details about the original error from Auth0.
    """

    def __init__(self, code: str, message: str, cause=None):
        super().__init__(message)
        self.code = code
        self.cause = cause

        # Extract additional error details if available
        if cause:
            self.error = getattr(cause, "error", None)
            self.error_description = getattr(cause, "error_description", None)
        else:
            self.error = None
            self.error_description = None
