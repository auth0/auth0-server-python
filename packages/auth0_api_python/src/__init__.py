"""
auth0-api-python

A lightweight Python SDK for verifying Auth0-issued access tokens
in server-side APIs, using Authlib for OIDC discovery and JWKS fetching.
"""

from .api_client import ApiClient
from .config import ApiClientOptions

__all__ = [
    "ApiClient",
    "ApiClientOptions"
]