"""
Configuration classes and utilities for auth0-api-python.
"""

from typing import Callable, Optional

from auth0_api_python.memory_token_store import MemoryTokenStore


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
        client_id: Optional required if you want to use get_access_token_for_connection.
        client_secret: Optional required if you want to use get_access_token_for_connection.
        token_store: Optional token store instance for caching tokens should have async get, set and delete methods.
        secret: Optional required if you want to use get_access_token_for_connection, defaults to client_secret.
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
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        token_store: Optional[object] = None,
        secret: Optional[str] = None,
    ):
        self.domain = domain
        self.audience = audience
        self.custom_fetch = custom_fetch
        self.dpop_enabled = dpop_enabled
        self.dpop_required = dpop_required
        self.dpop_iat_leeway = dpop_iat_leeway
        self.dpop_iat_offset = dpop_iat_offset
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_store = token_store or MemoryTokenStore()
        self.secret = secret or client_secret
