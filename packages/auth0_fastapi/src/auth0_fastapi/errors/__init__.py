from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse

#Imported from auth0-server-python
from auth0_server_python.error import (
    Auth0Error,
    MissingTransactionError,
    ApiError,
    AccessTokenError,
    MissingRequiredArgumentError,
    BackchannelLogoutError,
    AccessTokenForConnectionError
)

def auth0_exception_handler(request: Request, exc: Auth0Error):
    """
    Exception handler for Auth0 SDK errors.
    Maps different Auth0 errors to appropriate HTTP status codes.
    """
    # Set a default status code
    status_code = 400

    if isinstance(exc, MissingTransactionError):
        status_code = 404  # Not Found
    elif isinstance(exc, MissingRequiredArgumentError):
        status_code = 422  # Unprocessable Entity
    elif isinstance(exc, ApiError):
        status_code = 502  # Bad Gateway, indicates an upstream error
    elif isinstance(exc, AccessTokenError):
        status_code = 401  # Unauthorized
    elif isinstance(exc, BackchannelLogoutError):
        status_code = 400  # Bad Request
    elif isinstance(exc, AccessTokenForConnectionError):
        status_code = 400  # Bad Request

    return JSONResponse(
        status_code=status_code,
        content={
            "error": getattr(exc, "code", "auth_error"),
            "message": exc.message or "An authentication error occurred."
        }
    )

def register_exception_handlers(app):
    """
    Register all Auth0-related exception handlers with the FastAPI app.
    """
    app.add_exception_handler(Auth0Error, auth0_exception_handler)
