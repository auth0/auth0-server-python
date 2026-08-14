import secrets
import time
from typing import Union

import jwt

from auth0_server_python.error import ConfigurationError

# RFC 7523 client-assertion type for private_key_jwt authentication.
CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

# Assertion lifetime in seconds.
_ASSERTION_LIFETIME = 60


def validate_client_assertion_key(private_key: Union[str, bytes], alg: str = "RS256") -> None:
    """
    Verify the signing key and algorithm can produce a client assertion.

    Args:
        private_key: The client's private signing key (PKCS8 PEM string or bytes).
        alg: The signing algorithm (defaults to "RS256").

    Raises:
        ConfigurationError: If the key is malformed or does not match the algorithm.
    """
    try:
        jwt.encode({"probe": True}, private_key, algorithm=alg)
    except Exception as e:
        raise ConfigurationError(
            f"Invalid client_assertion_signing_key for algorithm {alg}: {e}"
        )


def build_client_assertion(
    private_key: Union[str, bytes],
    client_id: str,
    issuer: str,
    alg: str = "RS256",
) -> str:
    """
    Mint a private_key_jwt client assertion for token-endpoint authentication (RFC 7523).

    Args:
        private_key: The client's private signing key (PKCS8 PEM string or bytes).
        client_id: The Auth0 client ID, used as both the issuer and subject claim.
        issuer: The authorization server issuer identifier, used as the audience claim.
        alg: The signing algorithm (defaults to "RS256").

    Returns:
        The signed client-assertion JWT.
    """
    now = int(time.time())
    payload = {
        "iss": client_id,
        "sub": client_id,
        "aud": issuer,
        "iat": now,
        "nbf": now,
        "exp": now + _ASSERTION_LIFETIME,
        "jti": secrets.token_urlsafe(32),
    }
    return jwt.encode(payload, private_key, algorithm=alg)
