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
