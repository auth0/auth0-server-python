"""
Configuration classes and utilities for auth0-api-python.
"""

from typing import Optional, Callable

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
        custom_fetch: Optional[Callable[..., object]] = None
    ):
        self.domain = domain
        self.audience = audience
        self.custom_fetch = custom_fetch
