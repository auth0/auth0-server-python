"""
Pure helper functions for anonymous session operations.
"""

import base64
import json
from typing import Any, Optional

import httpx

from auth0_server_python.auth_types import (
    AnonymousSessionContext,
    AnonymousTokenSetEntry,
)
from auth0_server_python.error import (
    AnonymousSessionCreateError,
    AnonymousSessionError,
    AnonymousSessionTokenError,
    _AnonymousSessionExpired,
)

ANON_IDENTIFIER = "_a0_anon"

# Audience that mints the login-injection transfer ticket instead of an access token.
TRANSFER_AUDIENCE = "urn:auth0:anon_transfer"

_METADATA_MAX_BYTES = 1024


def normalize_url(value: Optional[str]) -> Optional[str]:
    """Normalize a domain-like value for comparison.

    Args:
        value: A domain or URL string, or None.

    Returns:
        The value lowercased, scheme-qualified, and without a trailing
        slash. Falsy input is returned unchanged.
    """
    if not value:
        return value
    value = value.lower()
    if value.startswith("https://"):
        pass
    elif value.startswith("http://"):
        value = value.replace("http://", "https://")
    else:
        value = f"https://{value}"
    return value.rstrip("/")


def decode_anonymous_sub(access_token: str) -> Optional[str]:
    """Extract the sub claim from a JWT access token without verifying the signature.

    Args:
        access_token: The token to decode.

    Returns:
        The sub claim, or None for opaque tokens, non-JWT strings, or
        tokens with no sub claim.
    """
    try:
        parts = access_token.split(".")
        if len(parts) != 3:
            return None
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        sub = payload.get("sub")
        if not isinstance(sub, str) or not sub.startswith("anon@"):
            return None
        return sub
    except Exception:
        return None


def find_token_set(
    token_sets: list,
    audience: Optional[str],
    scope: Optional[str],
) -> Optional[AnonymousTokenSetEntry]:
    """Return the cached token set for an audience/scope pair, or None."""
    for ts in token_sets:
        if ts.audience == audience and ts.scope == scope:
            return ts
    return None


def upsert_token_set(
    context: AnonymousSessionContext,
    entry: AnonymousTokenSetEntry,
) -> AnonymousSessionContext:
    """Return a copy of context with the token set for entry's audience/scope replaced."""
    new_sets = [
        ts for ts in context.token_sets
        if not (ts.audience == entry.audience and ts.scope == entry.scope)
    ]
    new_sets.append(entry)
    return context.model_copy(update={"token_sets": new_sets})


def parse_anonymous_error_body(response: httpx.Response) -> dict[str, Any]:
    """Parse an error response body as JSON.

    Args:
        response: The HTTP response to parse.

    Returns:
        The parsed JSON body, or a fallback dict with 'error_description'
        when the body is not valid JSON.
    """
    try:
        data = response.json()
    except (json.JSONDecodeError, ValueError):
        data = None
    if not isinstance(data, dict):
        return {
            "error_description": f"Request failed with status {response.status_code}",
        }
    return data


def map_anonymous_error(
    error_data: dict[str, Any],
    operation: str,
) -> Exception:
    """Map a server error response to a typed exception.

    Args:
        error_data: The parsed error response body.
        operation: One of 'create', 'token'.

    Returns:
        The exception instance. Does not raise it.
    """
    code = error_data.get("error", "")
    description = error_data.get("error_description") or f"Anonymous {operation} failed"

    if code in ("session_expired", "invalid_session_token"):
        return _AnonymousSessionExpired(description, original_code=code)

    if operation == "create":
        return AnonymousSessionCreateError(description, code=code or "anonymous_create_error", cause=error_data)
    if operation == "token":
        return AnonymousSessionTokenError(description, code=code or "anonymous_token_error", cause=error_data)
    return AnonymousSessionError(code or "anonymous_error", description, error_data)


def validate_metadata(metadata: Optional[dict[str, Any]]) -> None:
    """Validate metadata locally before it reaches the network.

    Args:
        metadata: The metadata dict to validate, or None.

    Raises:
        AnonymousSessionCreateError: metadata is not a dict, contains a
            a non-JSON-serializable value, or exceeds 1KB.
    """
    if metadata is None:
        return
    if not isinstance(metadata, dict):
        raise AnonymousSessionCreateError("metadata must be a JSON object", code="invalid_metadata")
    try:
        size = len(json.dumps(metadata, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8"))
    except (TypeError, ValueError) as e:
        raise AnonymousSessionCreateError(
            "metadata must contain only JSON-serializable values", code="invalid_metadata"
        ) from e
    if size > _METADATA_MAX_BYTES:
        raise AnonymousSessionCreateError(
            "metadata exceeds the 1KB size limit", code="metadata_too_large"
        )
