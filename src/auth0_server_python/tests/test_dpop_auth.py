import base64
import hashlib
import json

import httpx
import pytest
from jwcrypto import jwk

from auth0_server_python.auth_schemes.bearer_auth import BearerAuth
from auth0_server_python.auth_schemes.dpop_auth import DPoPAuth, _base64url
from auth0_server_python.auth_server.my_account_client import _make_auth


@pytest.fixture
def ec_key():
    return jwk.JWK.generate(kty="EC", crv="P-256")


def _decode_jwt_parts(token: str) -> tuple[dict, dict]:
    parts = token.split(".")
    header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    return header, payload


def test_dpop_headers_set(ec_key):
    auth = DPoPAuth(token="test_token", key=ec_key)
    request = httpx.Request("POST", "https://example.com/me/v1/authentication-methods")
    flow = auth.auth_flow(request)
    modified = next(flow)

    assert modified.headers["Authorization"] == "DPoP test_token"
    assert "DPoP" in modified.headers
    assert "Bearer" not in modified.headers["Authorization"]


def test_dpop_proof_structure(ec_key):
    auth = DPoPAuth(token="test_token", key=ec_key)
    request = httpx.Request("POST", "https://example.com/me/v1/authentication-methods")
    flow = auth.auth_flow(request)
    modified = next(flow)

    proof = modified.headers["DPoP"]
    header, payload = _decode_jwt_parts(proof)

    assert header["typ"] == "dpop+jwt"
    assert header["alg"] == "ES256"
    assert "jwk" in header
    assert header["jwk"]["kty"] == "EC"
    assert header["jwk"]["crv"] == "P-256"

    assert "jti" in payload
    assert payload["htm"] == "POST"
    assert payload["htu"] == "https://example.com/me/v1/authentication-methods"
    assert "iat" in payload
    assert "ath" in payload


def test_dpop_htm_binding(ec_key):
    auth = DPoPAuth(token="test_token", key=ec_key)

    get_request = httpx.Request("GET", "https://example.com/me/v1/factors")
    flow = auth.auth_flow(get_request)
    modified = next(flow)
    _, payload = _decode_jwt_parts(modified.headers["DPoP"])
    assert payload["htm"] == "GET"

    post_request = httpx.Request("post", "https://example.com/me/v1/factors")
    flow = auth.auth_flow(post_request)
    modified = next(flow)
    _, payload = _decode_jwt_parts(modified.headers["DPoP"])
    assert payload["htm"] == "POST"


def test_dpop_htu_strips_query_and_fragment(ec_key):
    auth = DPoPAuth(token="test_token", key=ec_key)
    request = httpx.Request("GET", "https://example.com/me/v1/factors?foo=bar#section")
    flow = auth.auth_flow(request)
    modified = next(flow)
    _, payload = _decode_jwt_parts(modified.headers["DPoP"])
    assert payload["htu"] == "https://example.com/me/v1/factors"


def test_dpop_htu_preserves_port(ec_key):
    auth = DPoPAuth(token="test_token", key=ec_key)
    request = httpx.Request("GET", "https://example.com:8443/me/v1/factors")
    flow = auth.auth_flow(request)
    modified = next(flow)
    _, payload = _decode_jwt_parts(modified.headers["DPoP"])
    assert payload["htu"] == "https://example.com:8443/me/v1/factors"


def test_dpop_ath_binding(ec_key):
    token = "my_access_token_value"
    auth = DPoPAuth(token=token, key=ec_key)
    request = httpx.Request("GET", "https://example.com/me/v1/factors")
    flow = auth.auth_flow(request)
    modified = next(flow)
    _, payload = _decode_jwt_parts(modified.headers["DPoP"])

    expected_ath = _base64url(hashlib.sha256(token.encode("ascii")).digest())
    assert payload["ath"] == expected_ath


def test_dpop_proof_uniqueness(ec_key):
    auth = DPoPAuth(token="test_token", key=ec_key)
    jtis = set()
    for _ in range(10):
        request = httpx.Request("GET", "https://example.com/me/v1/factors")
        flow = auth.auth_flow(request)
        modified = next(flow)
        _, payload = _decode_jwt_parts(modified.headers["DPoP"])
        jtis.add(payload["jti"])

    assert len(jtis) == 10


def test_dpop_repr_redacts_credentials(ec_key):
    auth = DPoPAuth(token="secret_access_token_value", key=ec_key)
    assert "secret_access_token_value" not in repr(auth)
    assert "secret_access_token_value" not in str(auth)
    assert "[REDACTED]" in repr(auth)
    assert "[REDACTED]" in str(auth)


def test_dpop_rejects_non_ec_key():
    rsa_key = jwk.JWK.generate(kty="RSA", size=2048)
    with pytest.raises(ValueError, match="EC P-256"):
        DPoPAuth(token="token", key=rsa_key)


def test_dpop_rejects_wrong_curve():
    p384_key = jwk.JWK.generate(kty="EC", crv="P-384")
    with pytest.raises(ValueError, match="EC P-256"):
        DPoPAuth(token="token", key=p384_key)


def test_make_auth_bearer_fallback():
    auth = _make_auth("token123", dpop_key=None)
    assert isinstance(auth, BearerAuth)


def test_make_auth_dpop_when_key_provided(ec_key):
    auth = _make_auth("token123", dpop_key=ec_key)
    assert isinstance(auth, DPoPAuth)
