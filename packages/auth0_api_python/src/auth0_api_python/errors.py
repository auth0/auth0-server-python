"""
Custom exceptions for auth0-api-python SDK
"""

class MissingRequiredArgumentError(Exception):
    """Error raised when a required argument is missing."""
    code = "missing_required_argument_error"

    def __init__(self, argument: str):
        super().__init__(f"The argument '{argument}' is required but was not provided.")
        self.argument = argument
        self.name = self.__class__.__name__


class VerifyAccessTokenError(Exception):
    """Error raised when verifying the access token fails."""
    code = "verify_access_token_error"

    def __init__(self, message: str):
        super().__init__(message)
        self.name = self.__class__.__name__


class GetTokenForConnectionError(Exception):
    """Error raised when verifying the access token fails."""
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