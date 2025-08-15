"""
Configuration classes and utilities for auth0-api-python.
"""

from typing import Optional, Callable

from auth0_api_python.errors import MissingRequiredArgumentError


class ApiClientOptions:
    """
    Configuration for the ApiClient.

    Args:
        domain: The Auth0 domain, e.g., "my-tenant.us.auth0.com".
        audience: The expected 'aud' claim in the token.
        custom_fetch: Optional callable that can replace the default HTTP fetch logic.
    """
    def __init__(
        self,
        domain: str,
        audience: str,
        custom_fetch: Optional[Callable[..., object]] = None,
        associated_client: Optional[dict] = None,
    ):
        self.domain = domain
        self.audience = audience
        self.custom_fetch = custom_fetch
        self.associated_client = associated_client
        if associated_client:
            if not associated_client.get("client_id"):
                raise MissingRequiredArgumentError("associated_client.client_id")
            if not associated_client.get("client_secret"):
                raise MissingRequiredArgumentError("associated_client.client_secret")
