"""
Configuration classes and utilities for auth0-api-python.
"""

from typing import Callable, Optional


from auth0_api_python.errors import MissingRequiredArgumentError


class ApiClientOptions:
    """
    Configuration for the ApiClient.

    Args:
        domain: The Auth0 domain, e.g., "my-tenant.us.auth0.com".
        audience: The expected 'aud' claim in the token.
        custom_fetch: Optional callable that can replace the default HTTP fetch logic.
        dpop_enabled: Whether DPoP is enabled (default: True for backward compatibility).
        dpop_required: Whether DPoP is required (default: False, allows both Bearer and DPoP).
        dpop_iat_leeway: Leeway in seconds for DPoP proof iat claim (default: 30).
        dpop_iat_offset: Maximum age in seconds for DPoP proof iat claim (default: 300).
        associated_client: Optional required if you want to use get_token_for_connection.
            Must be a dict with 'client_id' and 'client_secret' keys.
    """
    def __init__(
        self,
        domain: str,
        audience: str,
        custom_fetch: Optional[Callable[..., object]] = None,
        dpop_enabled: bool = True,
        dpop_required: bool = False,
        dpop_iat_leeway: int = 30,
        dpop_iat_offset: int = 300,
        associated_client: Optional[dict] = None,
    ):
        self.domain = domain
        self.audience = audience
        self.custom_fetch = custom_fetch
        self.dpop_enabled = dpop_enabled
        self.dpop_required = dpop_required
        self.dpop_iat_leeway = dpop_iat_leeway
        self.dpop_iat_offset = dpop_iat_offset
        self.associated_client = associated_client
        if associated_client:
            if not associated_client.get("client_id"):
                raise MissingRequiredArgumentError("associated_client.client_id")
            if not associated_client.get("client_secret"):
                raise MissingRequiredArgumentError("associated_client.client_secret")