"""
Utility functions for OIDC discovery and JWKS fetching (asynchronously) 
using httpx or a custom fetch approach.
"""

import httpx
import base64
import json
from typing import Any, Dict, Optional, Callable, Union

async def fetch_oidc_metadata(
    domain: str, 
    custom_fetch: Optional[Callable[..., Any]] = None
) -> Dict[str, Any]:
    """
    Asynchronously fetch the OIDC config from https://{domain}/.well-known/openid-configuration.
    Returns a dict with keys like issuer, jwks_uri, authorization_endpoint, etc.
    If custom_fetch is provided, we call it instead of httpx.
    """
    url = f"https://{domain}/.well-known/openid-configuration"
    if custom_fetch:
        response = await custom_fetch(url)
        return response.json() if hasattr(response, "json") else response
    else:
        async with httpx.AsyncClient() as client:
            resp = await client.get(url)
            resp.raise_for_status()
            return resp.json()


async def fetch_jwks(
    jwks_uri: str, 
    custom_fetch: Optional[Callable[..., Any]] = None
) -> Dict[str, Any]:
    """
    Asynchronously fetch the JSON Web Key Set from jwks_uri.
    Returns the raw JWKS JSON, e.g. {'keys': [...]}

    If custom_fetch is provided, it must be an async callable 
    that fetches data from the jwks_uri.
    """
    if custom_fetch:
        response = await custom_fetch(jwks_uri)
        return response.json() if hasattr(response, "json") else response
    else:
        async with httpx.AsyncClient() as client:
            resp = await client.get(jwks_uri)
            resp.raise_for_status()
            return resp.json()
        

async def get_unverified_header(token: Union[str, bytes]) -> dict:
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    try:
        header_b64, _, _ = token.split(".", 2)
    except ValueError:
        raise ValueError("Not enough segments in token")

    padding_needed = 4 - len(header_b64) % 4
    if padding_needed and padding_needed < 4:
        header_b64 += "=" * padding_needed

    header_data = base64.urlsafe_b64decode(header_b64)
    return json.loads(header_data)