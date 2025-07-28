"""
Utility functions for OIDC discovery and JWKS fetching (asynchronously) 
using httpx or a custom fetch approach.
"""

import httpx
import base64
import json
import hashlib
import uuid
from typing import Any, Dict, Optional, Callable, Union

from urllib.parse import urlparse, urlunparse

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
    """
    Parse the first segment (header) of a JWT without verifying signature.
    Ensures correct Base64 padding before decode to avoid garbage bytes.
    """
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    try:
        header_b64, _, _ = token.split(".", 2)
    except ValueError:
        raise ValueError("Not enough segments in token")
    
    header_b64 = remove_bytes_prefix(header_b64)

    header_b64 = fix_base64_padding(header_b64)

    header_data = base64.urlsafe_b64decode(header_b64)
    return json.loads(header_data)



def fix_base64_padding(segment: str) -> str:
    """
    If `segment`'s length is not a multiple of 4, add '=' padding 
    so that base64.urlsafe_b64decode won't produce nonsense bytes.
    No extra '=' added if length is already a multiple of 4.
    """
    remainder = len(segment) % 4
    if remainder == 0:
        return segment  # No additional padding needed
    return segment + ("=" * (4 - remainder))

def remove_bytes_prefix(s: str) -> str:
    """If the string looks like b'eyJh...', remove the leading b' and trailing '."""
    if s.startswith("b'"):
        return s[2:]  # cut off the leading b'
    return s

def normalize_url_for_htu(raw_url: str) -> str:
    """
    Normalize URL for DPoP htu comparison following RFC 3986.
    Matches the level of normalization that browsers typically do.
    """
    p = urlparse(raw_url)
    
    # Lowercase scheme and netloc (host)
    scheme = p.scheme.lower()
    netloc = p.netloc.lower()
    
    # Remove default ports
    if scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]
    
    # Ensure non-empty path for http(s)
    path = p.path
    if scheme in ("http", "https") and not path:
        path = "/"
    
    return urlunparse((scheme, netloc, path, "", "", ""))


def sha256_base64url(input_str: Union[str, bytes]) -> str:
    """
    Compute SHA-256 digest of the input string and return a
    Base64URL-encoded string *without* padding.
    """
    if isinstance(input_str, str):
        digest = hashlib.sha256(input_str.encode("utf-8")).digest()
    else:
        digest = hashlib.sha256(input_str).digest()
    b64 = base64.urlsafe_b64encode(digest).decode("utf-8")
    return b64.rstrip("=")

def calculate_jwk_thumbprint(jwk: Dict[str, str]) -> str:
    """
    Compute the RFC 7638 JWK thumbprint for a public JWK.

    - For EC keys, includes only: crv, kty, x, y
    - Serializes with no whitespace, keys sorted lexicographically
    - Hashes with SHA-256 and returns base64url-encoded string without padding
    """
    kty = jwk.get("kty")
    
    if kty == "EC":
        if not all(k in jwk for k in ["crv", "x", "y"]):
            raise ValueError("EC key missing required parameters")
        members = ("crv", "kty", "x", "y")
    else:
        raise ValueError(f"{kty}(Key Type) Parameter missing or unsupported ")

    # order the members and filter out any missing keys
    ordered = {k: jwk[k] for k in members if k in jwk}

    # Serialize to JSON with no whitespace, sorted keys
    thumbprint_json = json.dumps(ordered, separators=(",", ":"), sort_keys=True)

    #Using SHA-256 to hash the JSON string
    digest = hashlib.sha256(thumbprint_json.encode("utf-8")).digest()

    # Base64URL-encode the digest and remove padding
    return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")