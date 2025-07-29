"""
Custom exceptions for auth0-api-python SDK with HTTP response metadata
"""
from typing import Any


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

    def to_response_dict(self) -> dict[str, Any]:
        """Convert to a dictionary suitable for JSON response body."""
        return {
            "error": self.get_error_code(),
            "error_description": self.get_error_description()
        }


class MissingRequiredArgumentError(BaseAuthError):
    """Error raised when a required argument is missing."""

    def __init__(self, argument: str):
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
        return 401

    def get_error_code(self) -> str:
        return ""

    def get_error_description(self) -> str:
        return ""

