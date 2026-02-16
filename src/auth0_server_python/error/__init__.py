"""
Error classes for the auth0-server-python SDK.
These exceptions provide specific error types for different failure scenarios.
"""
from typing import Optional


class Auth0Error(Exception):
    """Base class for all Auth0 SDK errors."""

    def __init__(self, message=None):
        self.message = message
        super().__init__(message)


class MissingTransactionError(Auth0Error):
    """
    Error raised when a required transaction is missing.
    This typically happens during the callback phase when the transaction
    from the initial authorization request cannot be found.
    """
    code = "missing_transaction_error"

    def __init__(self, message=None):
        super().__init__(message or "The transaction is missing.")
        self.name = "MissingTransactionError"


class ApiError(Auth0Error):
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


class PollingApiError(ApiError):
    """
    Error raised when a polling API request to Auth0 fails.
    Contains details about the original error from Auth0 and the requested polling interval.
    """

    def __init__(self, code: str, message: str, interval: Optional[int], cause=None):
        super().__init__(code, message, cause)
        self.interval = interval

class MyAccountApiError(Auth0Error):
    """
    Error raised when an API request to My Account API fails.
    Contains details about the original error from Auth0.
    """

    def __init__(
            self,
            title: Optional[str],
            type: Optional[str],
            detail: Optional[str],
            status: Optional[int],
            validation_errors: Optional[list[dict[str, str]]] = None
        ):
        super().__init__(detail)
        self.title = title
        self.type = type
        self.detail = detail
        self.status = status
        self.validation_errors = validation_errors

class AccessTokenError(Auth0Error):
    """Error raised when there's an issue with access tokens."""

    def __init__(self, code: str, message: str, cause=None):
        super().__init__(message)
        self.code = code
        self.name = "AccessTokenError"
        self.cause = cause


class MissingRequiredArgumentError(Auth0Error):
    """
    Error raised when a required argument is missing.
    Includes the name of the missing argument in the error message.
    """
    code = "missing_required_argument_error"

    def __init__(self, argument: str):
        message = f"The argument '{argument}' is required but was not provided."
        super().__init__(message)
        self.name = "MissingRequiredArgumentError"
        self.argument = argument


class BackchannelLogoutError(Auth0Error):
    """
    Error raised during backchannel logout processing.
    This can happen when validating or processing logout tokens.
    """
    code = "backchannel_logout_error"

    def __init__(self, message: str):
        super().__init__(message)
        self.name = "BackchannelLogoutError"


class AccessTokenForConnectionError(Auth0Error):
    """Error when retrieving access tokens for a specific connection fails."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.name = "AccessTokenForConnectionError"

class StartLinkUserError(Auth0Error):
    """
    Error raised when user linking process fails to start.
    This typically happens when trying to link accounts without
    having an authenticated user first.
    """
    code = "start_link_user_error"

    def __init__(self, message: str):
        super().__init__(message)
        self.name = "StartLinkUserError"


# Error code enumerations - these can be used to identify specific error scenarios

class AccessTokenErrorCode:
    """Error codes for access token operations."""
    MISSING_SESSION = "missing_session"
    MISSING_REFRESH_TOKEN = "missing_refresh_token"
    FAILED_TO_REFRESH_TOKEN = "failed_to_refresh_token"
    FAILED_TO_REQUEST_TOKEN = "failed_to_request_token"
    REFRESH_TOKEN_ERROR = "refresh_token_error"
    AUTH_REQ_ID_ERROR = "auth_req_id_error"
    INCORRECT_AUDIENCE = "incorrect_audience"


class AccessTokenForConnectionErrorCode:
    """Error codes for connection-specific token operations."""
    MISSING_REFRESH_TOKEN = "missing_refresh_token"
    FAILED_TO_RETRIEVE = "failed_to_retrieve"
    API_ERROR = "api_error"
    FETCH_ERROR = "retrieval_error"
