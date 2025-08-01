import base64
import json
import time

import pytest
from auth0_api_python.api_client import ApiClient
from auth0_api_python.config import ApiClientOptions
from auth0_api_python.errors import (
    InvalidAuthSchemeError,
    InvalidDpopProofError,
    MissingAuthorizationError,
    MissingRequiredArgumentError,
    VerifyAccessTokenError,
)
from auth0_api_python.token_utils import (
    PRIVATE_EC_JWK,
    PRIVATE_JWK,
    generate_dpop_proof,
    generate_token,
    generate_token_with_cnf,
    sha256_base64url,
)
from pytest_httpx import HTTPXMock

# Create public RSA JWK by selecting only public key components
PUBLIC_RSA_JWK = {k: PRIVATE_JWK[k] for k in ["kty", "n", "e", "alg", "use", "kid"] if k in PRIVATE_JWK}

@pytest.mark.asyncio
async def test_init_missing_args():
    """
    Test that providing no audience or domain raises an error.
    """
    with pytest.raises(MissingRequiredArgumentError):
        _ = ApiClient(ApiClientOptions(domain="", audience="some_audience"))

    with pytest.raises(MissingRequiredArgumentError):
        _ = ApiClient(ApiClientOptions(domain="example.us.auth0.com", audience=""))


@pytest.mark.asyncio
async def test_verify_access_token_successfully(httpx_mock: HTTPXMock):
    """
    Test that a valid RS256 token with correct issuer, audience, iat, and exp
    is verified successfully by ApiClient.
    """
    httpx_mock.add_response(
        method="GET",
        url="https://auth0.local/.well-known/openid-configuration",
        json={
            "issuer": "https://auth0.local/",
            "jwks_uri": "https://auth0.local/.well-known/jwks.json"
        }
    )
    httpx_mock.add_response(
        method="GET",
        url="https://auth0.local/.well-known/jwks.json",
        json={
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "TEST_KEY",
                    "n": "whYOFK2Ocbbpb_zVypi9SeKiNUqKQH0zTKN1-6fpCTu6ZalGI82s7XK3tan4dJt90ptUPKD2zvxqTzFNfx4HHHsrYCf2-FMLn1VTJfQazA2BvJqAwcpW1bqRUEty8tS_Yv4hRvWfQPcc2Gc3-_fQOOW57zVy-rNoJc744kb30NjQxdGp03J2S3GLQu7oKtSDDPooQHD38PEMNnITf0pj-KgDPjymkMGoJlO3aKppsjfbt_AH6GGdRghYRLOUwQU-h-ofWHR3lbYiKtXPn5dN24kiHy61e3VAQ9_YAZlwXC_99GGtw_NpghFAuM4P1JDn0DppJldy3PGFC0GfBCZASw",
                    "e": "AQAB",
                    "alg": "RS256",
                    "use": "sig"
                }
            ]
        }
    )

    access_token = await generate_token(
        domain="auth0.local",
        user_id="user_123",
        audience="my-audience",    # sets 'aud'
        issuer=None,               # uses default "https://auth0.local/"
        iat=True,
        exp=True
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    # 5) Verify the token
    claims = await api_client.verify_access_token(access_token=access_token)
    assert claims["sub"] == "user_123"

@pytest.mark.asyncio
async def test_verify_access_token_fail_no_iss(httpx_mock: HTTPXMock):
    """
    Test that a token missing 'iss' claim fails verification.
    """

    httpx_mock.add_response(
        method="GET",
        url="https://auth0.local/.well-known/openid-configuration",
        json={
            "issuer": "https://auth0.local/",
            "jwks_uri": "https://auth0.local/.well-known/jwks.json"
        }
    )
    httpx_mock.add_response(
        method="GET",
        url="https://auth0.local/.well-known/jwks.json",
        json={
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "TEST_KEY",
                    "n": "whYOFK2Ocbbpb_zVypi9SeKiNUqKQH0zTKN1-6fpCTu6ZalGI82s7XK3tan4dJt90ptUPKD2zvxqTzFNfx4HHHsrYCf2-FMLn1VTJfQazA2BvJqAwcpW1bqRUEty8tS_Yv4hRvWfQPcc2Gc3-_fQOOW57zVy-rNoJc744kb30NjQxdGp03J2S3GLQu7oKtSDDPooQHD38PEMNnITf0pj-KgDPjymkMGoJlO3aKppsjfbt_AH6GGdRghYRLOUwQU-h-ofWHR3lbYiKtXPn5dN24kiHy61e3VAQ9_YAZlwXC_99GGtw_NpghFAuM4P1JDn0DppJldy3PGFC0GfBCZASw",
                    "e": "AQAB",
                    "alg": "RS256",
                    "use": "sig"
                }
            ]
        }
    )


    access_token = await generate_token(
        domain="auth0.local",
        user_id="user_123",
        audience="my-audience",
        issuer=False,  # skip 'iss'
        iat=True,
        exp=True
    )


    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )


    with pytest.raises(VerifyAccessTokenError) as err:
        await api_client.verify_access_token(access_token=access_token)

    assert "issuer mismatch" in str(err.value).lower() or "invalid iss" in str(err.value).lower()

@pytest.mark.asyncio
async def test_verify_access_token_fail_invalid_iss(httpx_mock: HTTPXMock):
    """
    Test that a token with an invalid issuer fails verification.
    """
    httpx_mock.add_response(
        method="GET",
        url="https://auth0.local/.well-known/openid-configuration",
        json={
            "issuer": "https://auth0.local/",
            "jwks_uri": "https://auth0.local/.well-known/jwks.json"
        }
    )
    httpx_mock.add_response(
        method="GET",
        url="https://auth0.local/.well-known/jwks.json",
        json={
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "TEST_KEY",
                    "n": "whYOFK2Ocbbpb_zVypi9SeKiNUqKQH0zTKN1-6fpCTu6ZalGI82s7XK3tan4dJt90ptUPKD2zvxqTzFNfx4HHHsrYCf2-FMLn1VTJfQazA2BvJqAwcpW1bqRUEty8tS_Yv4hRvWfQPcc2Gc3-_fQOOW57zVy-rNoJc744kb30NjQxdGp03J2S3GLQu7oKtSDDPooQHD38PEMNnITf0pj-KgDPjymkMGoJlO3aKppsjfbt_AH6GGdRghYRLOUwQU-h-ofWHR3lbYiKtXPn5dN24kiHy61e3VAQ9_YAZlwXC_99GGtw_NpghFAuM4P1JDn0DppJldy3PGFC0GfBCZASw",
                    "e": "AQAB",
                    "alg": "RS256",
                    "use": "sig"
                }
            ]
        }
    )

    access_token = await generate_token(
        domain="auth0.local",
        user_id="user_123",
        audience="my-audience",
        issuer="https://invalid-issuer.local",  # mismatch
        iat=True,
        exp=True
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    with pytest.raises(VerifyAccessTokenError) as err:
        await api_client.verify_access_token(access_token=access_token)

    assert "issuer mismatch" in str(err.value).lower() or "invalid iss" in str(err.value).lower()

@pytest.mark.asyncio
async def test_verify_access_token_fail_no_aud(httpx_mock: HTTPXMock):
    """
    Test that a token missing 'aud' claim fails verification.
    """
    httpx_mock.add_response(
        method="GET",
        url="https://auth0.local/.well-known/openid-configuration",
        json={
            "issuer": "https://auth0.local/",
            "jwks_uri": "https://auth0.local/.well-known/jwks.json"
        }
    )

    httpx_mock.add_response(
        method="GET",
        url="https://auth0.local/.well-known/jwks.json",
        json={
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "TEST_KEY",
                    "n": "whYOFK2Ocbbpb_zVypi9SeKiNUqKQH0zTKN1-6fpCTu6ZalGI82s7XK3tan4dJt90ptUPKD2zvxqTzFNfx4HHHsrYCf2-FMLn1VTJfQazA2BvJqAwcpW1bqRUEty8tS_Yv4hRvWfQPcc2Gc3-_fQOOW57zVy-rNoJc744kb30NjQxdGp03J2S3GLQu7oKtSDDPooQHD38PEMNnITf0pj-KgDPjymkMGoJlO3aKppsjfbt_AH6GGdRghYRLOUwQU-h-ofWHR3lbYiKtXPn5dN24kiHy61e3VAQ9_YAZlwXC_99GGtw_NpghFAuM4P1JDn0DppJldy3PGFC0GfBCZASw",
                    "e": "AQAB",
                    "alg": "RS256",
                    "use": "sig"
                }
            ]
        }
    )

    access_token = await generate_token(
        domain="auth0.local",
        user_id="user_123",
        audience=None,  # no 'aud' claim
        issuer=None,
        iat=True,
        exp=True
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    with pytest.raises(VerifyAccessTokenError) as err:
        await api_client.verify_access_token(access_token=access_token)

    assert "aud" in str(err.value).lower() or "audience" in str(err.value).lower()


@pytest.mark.asyncio
async def test_verify_access_token_fail_invalid_aud(httpx_mock: HTTPXMock):
    """
    Test that a token with an invalid audience fails verification.
    """

    httpx_mock.add_response(
        method="GET",
        url="https://auth0.local/.well-known/openid-configuration",
        json={
            "issuer": "https://auth0.local/",
            "jwks_uri": "https://auth0.local/.well-known/jwks.json"
        }
    )
    httpx_mock.add_response(
        method="GET",
        url="https://auth0.local/.well-known/jwks.json",
        json={
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "TEST_KEY",
                    "n": "whYOFK2Ocbbpb_zVypi9SeKiNUqKQH0zTKN1-6fpCTu6ZalGI82s7XK3tan4dJt90ptUPKD2zvxqTzFNfx4HHHsrYCf2-FMLn1VTJfQazA2BvJqAwcpW1bqRUEty8tS_Yv4hRvWfQPcc2Gc3-_fQOOW57zVy-rNoJc744kb30NjQxdGp03J2S3GLQu7oKtSDDPooQHD38PEMNnITf0pj-KgDPjymkMGoJlO3aKppsjfbt_AH6GGdRghYRLOUwQU-h-ofWHR3lbYiKtXPn5dN24kiHy61e3VAQ9_YAZlwXC_99GGtw_NpghFAuM4P1JDn0DppJldy3PGFC0GfBCZASw",
                    "e": "AQAB",
                    "alg": "RS256",
                    "use": "sig"
                }
            ]
        }
    )


    access_token = await generate_token(
        domain="auth0.local",
        user_id="user_123",
        audience="wrong-aud",  # mismatch from the config
        issuer=None,
        iat=True,
        exp=True
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    with pytest.raises(VerifyAccessTokenError) as err:
        await api_client.verify_access_token(access_token=access_token)


    error_str = str(err.value).lower()
    assert "audience mismatch" in error_str or "invalid aud" in error_str


@pytest.mark.asyncio
async def test_verify_access_token_fail_no_iat(httpx_mock: HTTPXMock):
    """
    Test that a token missing 'iat' claim fails verification.
    """
    httpx_mock.add_response(
        method="GET",
        url="https://auth0.local/.well-known/openid-configuration",
        json={
            "issuer": "https://auth0.local/",
            "jwks_uri": "https://auth0.local/.well-known/jwks.json"
        }
    )
    httpx_mock.add_response(
        method="GET",
        url="https://auth0.local/.well-known/jwks.json",
        json={
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "TEST_KEY",
                    "n": "whYOFK2Ocbbpb_zVypi9SeKiNUqKQH0zTKN1-6fpCTu6ZalGI82s7XK3tan4dJt90ptUPKD2zvxqTzFNfx4HHHsrYCf2-FMLn1VTJfQazA2BvJqAwcpW1bqRUEty8tS_Yv4hRvWfQPcc2Gc3-_fQOOW57zVy-rNoJc744kb30NjQxdGp03J2S3GLQu7oKtSDDPooQHD38PEMNnITf0pj-KgDPjymkMGoJlO3aKppsjfbt_AH6GGdRghYRLOUwQU-h-ofWHR3lbYiKtXPn5dN24kiHy61e3VAQ9_YAZlwXC_99GGtw_NpghFAuM4P1JDn0DppJldy3PGFC0GfBCZASw",
                    "e": "AQAB",
                    "alg": "RS256",
                    "use": "sig"
                }
            ]
        }
    )

    access_token = await generate_token(
        domain="auth0.local",
        user_id="user_123",
        audience="my-audience",
        issuer=None,
        iat=False,  # skip iat
        exp=True
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    with pytest.raises(VerifyAccessTokenError) as err:
        await api_client.verify_access_token(access_token=access_token)

    assert "iat" in str(err.value).lower() or "missing" in str(err.value).lower()


@pytest.mark.asyncio
async def test_verify_access_token_fail_no_exp(httpx_mock: HTTPXMock):
    """
    Test that a token missing 'exp' claim fails verification.
    """
    httpx_mock.add_response(
        method="GET",
        url="https://auth0.local/.well-known/openid-configuration",
        json={
            "issuer": "https://auth0.local/",
            "jwks_uri": "https://auth0.local/.well-known/jwks.json"
        }
    )
    httpx_mock.add_response(
        method="GET",
        url="https://auth0.local/.well-known/jwks.json",
        json={
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "TEST_KEY",
                    "n": "whYOFK2Ocbbpb_zVypi9SeKiNUqKQH0zTKN1-6fpCTu6ZalGI82s7XK3tan4dJt90ptUPKD2zvxqTzFNfx4HHHsrYCf2-FMLn1VTJfQazA2BvJqAwcpW1bqRUEty8tS_Yv4hRvWfQPcc2Gc3-_fQOOW57zVy-rNoJc744kb30NjQxdGp03J2S3GLQu7oKtSDDPooQHD38PEMNnITf0pj-KgDPjymkMGoJlO3aKppsjfbt_AH6GGdRghYRLOUwQU-h-ofWHR3lbYiKtXPn5dN24kiHy61e3VAQ9_YAZlwXC_99GGtw_NpghFAuM4P1JDn0DppJldy3PGFC0GfBCZASw",
                    "e": "AQAB",
                    "alg": "RS256",
                    "use": "sig"
                }
            ]
        }
    )


    access_token = await generate_token(
        domain="auth0.local",
        user_id="user_123",
        audience="my-audience",
        issuer=None,
        iat=True,
        exp=False  # skip exp
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    with pytest.raises(VerifyAccessTokenError) as err:
        await api_client.verify_access_token(access_token=access_token)


    error_str = str(err.value).lower()
    assert "exp" in error_str or "missing" in error_str


@pytest.mark.asyncio
async def test_verify_access_token_fail_no_audience_config():
    """
    Test that if the ApiClient doesn't get an audience in ApiClientOptions,
    it raises a MissingRequiredArgumentError or similar.
    """

    with pytest.raises(MissingRequiredArgumentError) as err:

        _ = ApiClient(

            ApiClientOptions(domain="auth0.local", audience="")
        )

    error_str = str(err.value).lower()
    assert "audience" in error_str and ("required" in error_str or "not provided" in error_str)

@pytest.mark.asyncio
async def test_verify_access_token_fail_malformed_token():
    """Test that a malformed token fails verification."""

    api_client = ApiClient(ApiClientOptions(domain="auth0.local", audience="my-audience"))

    with pytest.raises(VerifyAccessTokenError)   as e:
        await api_client.verify_access_token("header.payload")
    assert "failed to parse token" in str(e.value).lower()

    with pytest.raises(VerifyAccessTokenError) as e:
        await api_client.verify_access_token("header.pay!load.signature")
    assert "failed to parse token" in str(e.value).lower()



# DPOP PROOF VERIFICATION TESTS

# --- Core Success Tests ---

@pytest.mark.asyncio
async def test_verify_dpop_proof_successfully():
    """
    Test that a valid DPoP proof is verified successfully by ApiClient.
    """
    access_token = "test_token"
    dpop_proof = await generate_dpop_proof(
        access_token=access_token,
        http_method="GET",
        http_url="https://api.example.com/resource"
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    # Verify the DPoP proof
    claims = await api_client.verify_dpop_proof(
        access_token=access_token,
        proof=dpop_proof,
        http_method="GET",
        http_url="https://api.example.com/resource"
    )
    assert claims["jti"] # Verify it has the required jti claim
    assert claims["htm"] == "GET"
    assert claims["htu"] == "https://api.example.com/resource"
    assert isinstance(claims["iat"], int)
    expected_ath = sha256_base64url(access_token)
    assert claims["ath"] == expected_ath


# --- Header Validation Tests ---

@pytest.mark.asyncio
async def test_verify_dpop_proof_fail_no_access_token():
    """
    Test that verify_dpop_proof fails when access_token is missing.
    """
    dpop_proof = await generate_dpop_proof(
        access_token="test_token",
        http_method="GET",
        http_url="https://api.example.com/resource"
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    with pytest.raises(MissingRequiredArgumentError) as err:
        await api_client.verify_dpop_proof(
            access_token="",  # Empty access token
            proof=dpop_proof,
            http_method="GET",
            http_url="https://api.example.com/resource"
        )

    assert "access_token" in str(err.value).lower()

@pytest.mark.asyncio
async def test_verify_dpop_proof_fail_no_dpop_proof():
    """
    Test that verify_dpop_proof fails when dpop_proof is missing.
    """
    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    with pytest.raises(MissingRequiredArgumentError) as err:
        await api_client.verify_dpop_proof(
            access_token="test_token",
            proof="",  # Empty proof
            http_method="GET",
            http_url="https://api.example.com/resource"
        )

    assert "dpop_proof" in str(err.value).lower()

@pytest.mark.asyncio
async def test_verify_dpop_proof_fail_no_http_method_url():
    """
    Test that verify_dpop_proof fails when http_method or http_url is missing.
    """
    access_token = "test_token"
    dpop_proof = await generate_dpop_proof(
        access_token=access_token,
        http_method="GET",
        http_url="https://api.example.com/resource"
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    with pytest.raises(MissingRequiredArgumentError) as err:
        await api_client.verify_dpop_proof(
            access_token=access_token,
            proof=dpop_proof,
            http_method="",  # Empty method
            http_url="https://api.example.com/resource"
        )

    assert "http_method" in str(err.value).lower()

@pytest.mark.asyncio
async def test_verify_dpop_proof_fail_no_http_url():
    """
    Test that verify_dpop_proof fails when http_url is missing.
    """
    access_token = "test_token"
    dpop_proof = await generate_dpop_proof(
        access_token=access_token,
        http_method="GET",
        http_url="https://api.example.com/resource"
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    with pytest.raises(MissingRequiredArgumentError) as err:
        await api_client.verify_dpop_proof(
            access_token=access_token,
            proof=dpop_proof,
            http_method="GET",
            http_url="" # Empty url
        )

    assert "http_url" in str(err.value).lower()


# --- Claim Validation Tests ---

@pytest.mark.asyncio
async def test_verify_dpop_proof_fail_no_typ():
    """
    Test that a DPoP proof missing 'typ' header fails verification.
    """
    access_token = "test_token"
    dpop_proof = await generate_dpop_proof(
        access_token=access_token,
        http_method="GET",
        http_url="https://api.example.com/resource",
        header_overrides={"typ": None}  # Remove typ header
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    with pytest.raises(InvalidDpopProofError) as err:
        await api_client.verify_dpop_proof(
            access_token=access_token,
            proof=dpop_proof,
            http_method="GET",
            http_url="https://api.example.com/resource"
        )

    assert "unexpected jwt 'typ'" in str(err.value).lower()

@pytest.mark.asyncio
async def test_verify_dpop_proof_fail_invalid_typ():
    """
    Test that a DPoP proof with invalid 'typ' header fails verification.
    """
    access_token = "test_token"
    dpop_proof = await generate_dpop_proof(
        access_token=access_token,
        http_method="GET",
        http_url="https://api.example.com/resource",
        header_overrides={"typ": "jwt"}  # Wrong typ value
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    with pytest.raises(InvalidDpopProofError) as err:
        await api_client.verify_dpop_proof(
            access_token=access_token,
            proof=dpop_proof,
            http_method="GET",
            http_url="https://api.example.com/resource"
        )

    assert "unexpected jwt 'typ'" in str(err.value).lower()

@pytest.mark.asyncio
async def test_verify_dpop_proof_fail_invalid_alg():
    """
    Test that a DPoP proof with unsupported algorithm fails verification.
    """
    access_token = "test_token"

    valid_proof = await generate_dpop_proof(
        access_token=access_token,
        http_method="GET",
        http_url="https://api.example.com/resource"
    )

    parts = valid_proof.split('.')
    header = json.loads(base64.urlsafe_b64decode(parts[0] + '==').decode('utf-8'))
    header['alg'] = 'RS256'  # Invalid algorithm for DPoP (should be ES256)

    modified_header = base64.urlsafe_b64encode(
        json.dumps(header, separators=(',', ':')).encode('utf-8')
    ).decode('utf-8').rstrip('=')

    invalid_proof = f"{modified_header}.{parts[1]}.{parts[2]}"

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    with pytest.raises(InvalidDpopProofError) as err:
        await api_client.verify_dpop_proof(
            access_token=access_token,
            proof=invalid_proof,
            http_method="GET",
            http_url="https://api.example.com/resource"
        )

    assert "unsupported alg" in str(err.value).lower()

@pytest.mark.asyncio
async def test_verify_dpop_proof_fail_no_jwk():
    """
    Test that a DPoP proof missing 'jwk' header fails verification.
    """
    access_token = "test_token"
    dpop_proof = await generate_dpop_proof(
        access_token=access_token,
        http_method="GET",
        http_url="https://api.example.com/resource",
        header_overrides={"jwk": None}  # Remove jwk header
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    with pytest.raises(InvalidDpopProofError) as err:
        await api_client.verify_dpop_proof(
            access_token=access_token,
            proof=dpop_proof,
            http_method="GET",
            http_url="https://api.example.com/resource"
        )

    assert "missing or invalid jwk" in str(err.value).lower()

@pytest.mark.asyncio
async def test_verify_dpop_proof_fail_invalid_jwk_format():
    """
    Test that a DPoP proof with invalid 'jwk' format fails verification.
    """
    access_token = "test_token"
    dpop_proof = await generate_dpop_proof(
        access_token=access_token,
        http_method="GET",
        http_url="https://api.example.com/resource",
        header_overrides={"jwk": "invalid_jwk"}  # Invalid jwk format
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    with pytest.raises(InvalidDpopProofError) as err:
        await api_client.verify_dpop_proof(
            access_token=access_token,
            proof=dpop_proof,
            http_method="GET",
            http_url="https://api.example.com/resource"
        )

    assert "missing or invalid jwk" in str(err.value).lower()

@pytest.mark.asyncio
async def test_verify_dpop_proof_fail_private_key_in_jwk():
    """
    Test that a DPoP proof with private key material in jwk fails verification.
    """

    access_token = "test_token"
    # Include private key material (the 'd' parameter)
    invalid_jwk = dict(PRIVATE_EC_JWK)  # This includes the 'd' parameter

    dpop_proof = await generate_dpop_proof(
        access_token=access_token,
        http_method="GET",
        http_url="https://api.example.com/resource",
        header_overrides={"jwk": invalid_jwk}  # JWK with private key material
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    with pytest.raises(InvalidDpopProofError) as err:
        await api_client.verify_dpop_proof(
            access_token=access_token,
            proof=dpop_proof,
            http_method="GET",
            http_url="https://api.example.com/resource"
        )

    assert "private key" in str(err.value).lower()

@pytest.mark.asyncio
async def test_verify_dpop_proof_with_missing_jwk_parameters():
    """Test verify_dpop_proof with missing JWK parameters."""
    access_token = "test_token"

    incomplete_jwk = {"kty": "RSA"}

    dpop_proof = await generate_dpop_proof(
        access_token=access_token,
        http_method="GET",
        http_url="https://api.example.com/resource",
        header_overrides={"jwk": incomplete_jwk}
    )

    api_client = ApiClient(ApiClientOptions(domain="auth0.local", audience="my-audience"))
    with pytest.raises(InvalidDpopProofError) as err:
        await api_client.verify_dpop_proof(
            access_token=access_token,
            proof=dpop_proof,
            http_method="GET",
            http_url="https://api.example.com/resource"
        )
    assert "only ec keys are supported" in str(err.value).lower()

# --- IAT (Issued At Time) Validation Tests ---

@pytest.mark.asyncio
async def test_verify_dpop_proof_fail_no_iat():
    """
    Test that a DPoP proof missing 'iat' claim fails verification.
    """
    access_token = "test_token"
    dpop_proof = await generate_dpop_proof(
        access_token=access_token,
        http_method="GET",
        http_url="https://api.example.com/resource",
        iat=False  # Skip iat claim
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    with pytest.raises(InvalidDpopProofError) as err:
        await api_client.verify_dpop_proof(
            access_token=access_token,
            proof=dpop_proof,
            http_method="GET",
            http_url="https://api.example.com/resource"
        )

    assert "missing required claim" in str(err.value).lower()

@pytest.mark.asyncio
async def test_verify_dpop_proof_fail_invalid_iat_in_future():
    """
     Test IAT validation with a timestamp in the future.
    """
    access_token = "test_token"
    # Use a future timestamp (more than leeway allows)
    future_time = int(time.time()) + 3600  # 1 hour in the future
    dpop_proof = await generate_dpop_proof(
        access_token=access_token,
        http_method="GET",
        http_url="https://api.example.com/resource",
        iat_time=future_time  # Invalid future timestamp
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    with pytest.raises(InvalidDpopProofError) as err:
        await api_client.verify_dpop_proof(
            access_token=access_token,
            proof=dpop_proof,
            http_method="GET",
            http_url="https://api.example.com/resource"
        )

    assert "iat is from the future" in str(err.value).lower()

@pytest.mark.asyncio
async def test_verify_dpop_proof_iat_exact_boundary_conditions():
    """
    Test IAT timing validation at exact boundary conditions.
    """
    access_token = "test_token"

    # Test with timestamp exactly at the leeway boundary (should pass)
    current_time = int(time.time())
    boundary_time = current_time + 30  # Exactly at default leeway limit

    dpop_proof = await generate_dpop_proof(
        access_token=access_token,
        http_method="GET",
        http_url="https://api.example.com/resource",
        iat_time=boundary_time
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    # Should succeed as it's within leeway
    result = await api_client.verify_dpop_proof(
        access_token=access_token,
        proof=dpop_proof,
        http_method="GET",
        http_url="https://api.example.com/resource"
    )

    assert result is not None

@pytest.mark.asyncio
async def test_verify_dpop_proof_iat_in_past():
    """
    Test IAT validation with timestamp in the past.
    """
    access_token = "test_token"
    # Use a timestamp too far in the past
    past_time = int(time.time()) - 3600  # 1 hour ago
    dpop_proof = await generate_dpop_proof(
        access_token=access_token,
        http_method="GET",
        http_url="https://api.example.com/resource",
        iat_time=past_time
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    with pytest.raises(InvalidDpopProofError) as err:
        await api_client.verify_dpop_proof(
            access_token=access_token,
            proof=dpop_proof,
            http_method="GET",
            http_url="https://api.example.com/resource"
        )

    assert "iat is too old" in str(err.value).lower()

@pytest.mark.asyncio
async def test_verify_dpop_proof_iat_within_leeway():
    """
    Test that IAT timestamps within acceptable leeway pass validation.
    """
    access_token = "test_token"
    current_time = int(time.time())

    # Test within acceptable skew (should pass)
    dpop_proof = await generate_dpop_proof(
        access_token=access_token,
        http_method="GET",
        http_url="https://api.example.com/resource",
        iat_time=current_time - 30  # 30 seconds ago, should be acceptable
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    # This should succeed due to clock skew tolerance
    result = await api_client.verify_dpop_proof(
        access_token=access_token,
        proof=dpop_proof,
        http_method="GET",
        http_url="https://api.example.com/resource"
    )
    assert result is not None

# --- JTI (JWT ID) Validation Tests ---

@pytest.mark.asyncio
async def test_verify_dpop_proof_fail_empty_jti():
    """
    Test that a DPoP proof with empty 'jti' claim fails verification.
    """
    access_token = "test_token"
    dpop_proof = await generate_dpop_proof(
        access_token=access_token,
        http_method="GET",
        http_url="https://api.example.com/resource",
        jti=""  # Empty jti claim
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    with pytest.raises(InvalidDpopProofError) as err:
        await api_client.verify_dpop_proof(
            access_token=access_token,
            proof=dpop_proof,
            http_method="GET",
            http_url="https://api.example.com/resource"
        )

    assert "jti claim must not be empty" in str(err.value).lower()

@pytest.mark.asyncio
async def test_verify_dpop_proof_custom_jti_value():
    """
    Test for a custom JTI value.
    """
    access_token = "test_token"

    custom_jti = "unique-jti-12345"
    dpop_proof = await generate_dpop_proof(
        access_token=access_token,
        http_method="GET",
        http_url="https://api.example.com/resource",
        jti=custom_jti  # Use jti parameter instead of claims
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    # First verification should succeed
    result = await api_client.verify_dpop_proof(
        access_token=access_token,
        proof=dpop_proof,
        http_method="GET",
        http_url="https://api.example.com/resource"
    )

    assert result is not None
    assert result["jti"] == custom_jti

@pytest.mark.asyncio
async def test_verify_dpop_proof_with_missing_jti():
    """Test verify_dpop_proof with missing jti claim."""
    access_token = "test_token"

    # Generate DPoP proof WITHOUT jti claim from the start
    dpop_proof = await generate_dpop_proof(
        access_token=access_token,
        http_method="GET",
        http_url="https://api.example.com/resource",
        include_jti=False  # Completely omit jti claim
    )

    api_client = ApiClient(ApiClientOptions(domain="auth0.local", audience="my-audience"))
    with pytest.raises(InvalidDpopProofError) as err:
        await api_client.verify_dpop_proof(
            access_token=access_token,
            proof=dpop_proof,
            http_method="GET",
            http_url="https://api.example.com/resource"
        )
    assert "missing required claim: jti" in str(err.value).lower()

@pytest.mark.asyncio
async def test_verify_dpop_proof_fail_htm_mismatch():
    """
    Test that a DPoP proof with mismatched 'htm' claim fails verification.
    """
    access_token = "test_token"
    dpop_proof = await generate_dpop_proof(
        access_token=access_token,
        http_method="POST",  # Generate proof for POST
        http_url="https://api.example.com/resource",
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    with pytest.raises(InvalidDpopProofError) as err:
        await api_client.verify_dpop_proof(
            access_token=access_token,
            proof=dpop_proof,
            http_method="GET",  # But verify with GET
            http_url="https://api.example.com/resource"
        )

    assert "htm mismatch" in str(err.value).lower()

# --- HTU (HTTP URI) Validation Tests ---

@pytest.mark.asyncio
async def test_verify_dpop_proof_fail_htu_mismatch():
    """
    Test that a DPoP proof with mismatched 'htu' claim fails verification.
    """
    access_token = "test_token"
    dpop_proof = await generate_dpop_proof(
        access_token=access_token,
        http_method="GET",
        http_url="https://api.example.com/wrong-resource",  # Generate proof for wrong URL
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    with pytest.raises(InvalidDpopProofError) as err:
        await api_client.verify_dpop_proof(
            access_token=access_token,
            proof=dpop_proof,
            http_method="GET",
            http_url="https://api.example.com/resource"  # But verify with correct URL
        )

    assert "htu mismatch" in str(err.value).lower()

@pytest.mark.asyncio
async def test_verify_dpop_proof_htu_url_normalization_case_sensitivity():
    """
    Test HTU URL normalization handles case sensitivity correctly.
    """
    access_token = "test_token"

    # Test with different case in domain (should be normalized and pass)
    dpop_proof = await generate_dpop_proof(
        access_token=access_token,
        http_method="GET",
        http_url="https://API.EXAMPLE.COM/resource"  # Uppercase domain
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    # This should succeed due to URL normalization
    result = await api_client.verify_dpop_proof(
        access_token=access_token,
        proof=dpop_proof,
        http_method="GET",
        http_url="https://api.example.com/resource"  # Lowercase domain
    )
    assert result is not None


@pytest.mark.asyncio
async def  test_verify_dpop_proof_htu_trailing_slash_mismatch():
    """
    Test that HTU URLs with trailing slash differences cause verification failure.
    """
    access_token = "test_token"
    # Generate proof with trailing slash
    dpop_proof = await generate_dpop_proof(
        access_token=access_token,
        http_method="GET",
        http_url="https://api.example.com/resource/"
    )
    api_client = ApiClient(ApiClientOptions(domain="auth0.local", audience="my-audience"))
    with pytest.raises(InvalidDpopProofError) as err:
        await api_client.verify_dpop_proof(
            access_token=access_token,
            proof=dpop_proof,
            http_method="GET",
            http_url="https://api.example.com/resource"
        )
    assert "htu mismatch" in str(err.value).lower()

@pytest.mark.asyncio
async def test_verify_dpop_proof_htu_query_parameters():
    """
    Test HTU URL validation with query parameters - normalized behavior.
    Query parameters are stripped during normalization, so different params should succeed.
    """
    access_token = "test_token"

    # Test with query parameters (should be normalized)
    dpop_proof = await generate_dpop_proof(
        access_token=access_token,
        http_method="GET",
        http_url="https://api.example.com/resource?param1=value1"  # With query params
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    # This should succeed due to URL normalization
    result = await api_client.verify_dpop_proof(
        access_token=access_token,
        proof=dpop_proof,
        http_method="GET",
        http_url="https://api.example.com/resource?param2=value2"  # Different query params
    )
    assert result is not None


@pytest.mark.asyncio
async def test_verify_dpop_proof_htu_port_numbers():
    """
    Test HTU URL validation with explicit port numbers - normalized behavior.
    Default ports (443 for HTTPS, 80 for HTTP) are stripped during normalization.
    """
    access_token = "test_token"

    # Test with explicit default port (should be normalized)
    dpop_proof = await generate_dpop_proof(
        access_token=access_token,
        http_method="GET",
        http_url="https://api.example.com:443/resource"  # Explicit HTTPS port
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    # This should succeed due to URL normalization
    result = await api_client.verify_dpop_proof(
        access_token=access_token,
        proof=dpop_proof,
        http_method="GET",
        http_url="https://api.example.com/resource"  # Implicit HTTPS port
    )
    assert result is not None

@pytest.mark.asyncio
async def test_verify_dpop_proof_htu_fragment_handling():
    """
    Test HTU URL validation ignores fragments.
    """
    access_token = "test_token"

    # Test with fragment (should be ignored)
    dpop_proof = await generate_dpop_proof(
        access_token=access_token,
        http_method="GET",
        http_url="https://api.example.com/resource#fragment1"  # With fragment
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    # This should succeed as fragments are ignored
    result = await api_client.verify_dpop_proof(
        access_token=access_token,
        proof=dpop_proof,
        http_method="GET",
        http_url="https://api.example.com/resource#fragment2"  # Different fragment
    )
    assert result is not None

@pytest.mark.asyncio
async def test_verify_dpop_proof_fail_ath_mismatch():
    """
    Test that a DPoP proof with mismatched 'ath' claim fails verification.
    """
    access_token = "test_token"
    wrong_token = "wrong_token"

    dpop_proof = await generate_dpop_proof(
        access_token=wrong_token,  # Generate proof for wrong token
        http_method="GET",
        http_url="https://api.example.com/resource",
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    with pytest.raises(InvalidDpopProofError) as err:
        await api_client.verify_dpop_proof(
            access_token=access_token,  # But verify with correct token
            proof=dpop_proof,
            http_method="GET",
            http_url="https://api.example.com/resource"
        )

    assert "ath" in str(err.value).lower() or "hash" in str(err.value).lower()

@pytest.mark.asyncio
async def test_verify_dpop_proof_with_invalid_signature():
    """Test verify_dpop_proof with invalid signature."""
    access_token = "test_token"

    valid_proof = await generate_dpop_proof(
        access_token=access_token,
        http_method="GET",
        http_url="https://api.example.com/resource"
    )

    parts = valid_proof.split('.')
    if len(parts) == 3:
        header, payload, signature = parts
        tampered_proof = f"{header}.{payload}.{signature[:-5]}12345"
    else:
        tampered_proof = valid_proof

    api_client = ApiClient(ApiClientOptions(domain="auth0.local", audience="my-audience"))
    with pytest.raises(InvalidDpopProofError) as e:
        await api_client.verify_dpop_proof(
            access_token=access_token,
            proof=tampered_proof,
            http_method="GET",
            http_url="https://api.example.com/resource"
        )
    assert "signature verification failed" in str(e.value).lower()

# VERIFY_REQUEST TESTS

# --- Success Tests ---

@pytest.mark.asyncio
async def test_verify_request_bearer_scheme_success(httpx_mock: HTTPXMock):
    """
    Test successful Bearer token verification through verify_request.
    """
    # Mock OIDC discovery
    httpx_mock.add_response(
        method="GET",
        url="https://auth0.local/.well-known/openid-configuration",
        json={
            "jwks_uri": "https://auth0.local/.well-known/jwks.json",
            "issuer": "https://auth0.local/",
        },
    )

    # Mock JWKS endpoint
    httpx_mock.add_response(
        method="GET",
        url="https://auth0.local/.well-known/jwks.json",
        json={"keys": [PUBLIC_RSA_JWK]},
    )

    # Generate a valid Bearer token
    token = await generate_token(
        domain="auth0.local",
        user_id="test_user",
        audience="my-audience",
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    # Test Bearer scheme
    result = await api_client.verify_request(
        headers={"authorization": f"Bearer {token}"},
        http_method="GET",
        http_url="https://api.example.com/resource"
    )

    assert "sub" in result
    assert result["aud"] == "my-audience"
    assert result["iss"] == "https://auth0.local/"

@pytest.mark.asyncio
async def test_verify_request_dpop_scheme_success(httpx_mock: HTTPXMock):
    """
    Test successful DPoP token verification through verify_request.
    """
    # Mock OIDC discovery
    httpx_mock.add_response(
        method="GET",
        url="https://auth0.local/.well-known/openid-configuration",
        json={
            "jwks_uri": "https://auth0.local/.well-known/jwks.json",
            "issuer": "https://auth0.local/",
        },
    )

    # Mock JWKS endpoint
    httpx_mock.add_response(
        method="GET",
        url="https://auth0.local/.well-known/jwks.json",
        json={"keys": [PUBLIC_RSA_JWK]},
    )

    # Generate DPoP bound token and proof
    access_token = await generate_token_with_cnf(
        domain="auth0.local",
        user_id="test_user",
        audience="my-audience",
    )
    dpop_proof = await generate_dpop_proof(
        access_token=access_token,
        http_method="GET",
        http_url="https://api.example.com/resource"
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    # Test DPoP scheme
    result = await api_client.verify_request(
        headers={"authorization": f"DPoP {access_token}", "dpop": dpop_proof},
        http_method="GET",
        http_url="https://api.example.com/resource"
    )

    assert "sub" in result
    assert result["aud"] == "my-audience"
    assert result["iss"] == "https://auth0.local/"


# --- Configuration & Error Handling Tests ---

@pytest.mark.asyncio
async def test_verify_request_fail_dpop_required_mode():
    """
    Test that Bearer tokens are rejected when DPoP is required.
    """
    # Generate a valid Bearer token
    token = await generate_token(
        domain="auth0.local",
        user_id="test_user",
        audience="my-audience",
    )

    api_client = ApiClient(
        ApiClientOptions(
            domain="auth0.local",
            audience="my-audience",
            dpop_required=True  # Require DPoP
        )
    )

    with pytest.raises(InvalidAuthSchemeError) as err:
        await api_client.verify_request(
            headers={"authorization": f"Bearer {token}"},
            http_method="GET",
            http_url="https://api.example.com/resource"
        )

    assert "expected 'dpop', but got 'bearer'" in str(err.value).lower()

@pytest.mark.asyncio
async def test_verify_request_fail_dpop_enabled_bearer_with_cnf_conflict(httpx_mock: HTTPXMock):
    """
    Test that Bearer tokens with cnf claim are rejected when DPoP is enabled.
    """
    # Mock OIDC discovery
    httpx_mock.add_response(
        method="GET",
        url="https://auth0.local/.well-known/openid-configuration",
        json={
            "jwks_uri": "https://auth0.local/.well-known/jwks.json",
            "issuer": "https://auth0.local/",
        },
    )

    # Mock JWKS endpoint
    httpx_mock.add_response(
        method="GET",
        url="https://auth0.local/.well-known/jwks.json",
        json={"keys": [PUBLIC_RSA_JWK]},
    )

    # Generate a token with cnf claim (DPoP-bound token)
    token = await generate_token_with_cnf(
        domain="auth0.local",
        user_id="test_user",
        audience="my-audience",
    )

    api_client = ApiClient(
        ApiClientOptions(
            domain="auth0.local",
            audience="my-audience",
            dpop_enabled=True  # DPoP enabled
        )
    )

    with pytest.raises(InvalidAuthSchemeError) as err:
        await api_client.verify_request(
            headers={"authorization": f"Bearer {token}"},
            http_method="GET",
            http_url="https://api.example.com/resource"
        )

    assert "request's authorization http header scheme is not dpop" in str(err.value).lower()

@pytest.mark.asyncio
async def test_verify_request_fail_dpop_disabled():
    """
    Test that DPoP tokens are rejected when DPoP is disabled.
    """
    access_token = "test_token"
    dpop_proof = await generate_dpop_proof(
        access_token=access_token,
        http_method="GET",
        http_url="https://api.example.com/resource"
    )

    api_client = ApiClient(
        ApiClientOptions(
            domain="auth0.local",
            audience="my-audience",
            dpop_enabled=False  # DPoP disabled
        )
    )

    with pytest.raises(MissingAuthorizationError) as err:
        await api_client.verify_request(
            headers={"authorization": f"DPoP {access_token}", "dpop": dpop_proof},
            http_method="GET",
            http_url="https://api.example.com/resource"
        )

    assert err.value.get_status_code() == 401

@pytest.mark.asyncio
async def test_verify_request_fail_missing_authorization_header():
    """
    Test that requests without Authorization header are rejected.
    """
    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    with pytest.raises(MissingAuthorizationError) as err:
        await api_client.verify_request(
            headers={},
            http_method="GET",
            http_url="https://api.example.com/resource"
        )
    assert err.value.get_status_code() == 401

@pytest.mark.asyncio
async def test_verify_request_fail_unsupported_scheme():
    """
    Test that unsupported authentication schemes are rejected.
    """
    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    with pytest.raises(MissingAuthorizationError) as err:
        await api_client.verify_request(
            headers={"authorization": "Basic dXNlcjpwYXNz"},
            http_method="GET",
            http_url="https://api.example.com/resource"
        )
    assert err.value.get_status_code() == 401

@pytest.mark.asyncio
async def test_verify_request_fail_empty_bearer_token():
    """Test verify_request with empty token value."""
    api_client = ApiClient(ApiClientOptions(domain="auth0.local", audience="my-audience"))
    with pytest.raises(MissingAuthorizationError) as err:
        await api_client.verify_request({"Authorization": "Bearer "})
    assert err.value.get_status_code() == 401

@pytest.mark.asyncio
async def test_verify_request_with_multiple_spaces_in_authorization():
    """Test verify_request with authorization header containing multiple spaces."""
    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )
    with pytest.raises(InvalidAuthSchemeError) as err:
        await api_client.verify_request({"authorization": "Bearer  token  with  extra  spaces"})
    assert "authorization" in str(err.value).lower()

@pytest.mark.asyncio
async def test_verify_request_fail_missing_dpop_header():
    """
    Test that DPoP scheme requests without DPoP header are rejected.
    """
    access_token = "test_token"

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    with pytest.raises(InvalidDpopProofError) as err:
        await api_client.verify_request(
            headers={"authorization": f"DPoP {access_token}"},  # Missing DPoP header
            http_method="GET",
            http_url="https://api.example.com/resource"
        )

    assert "request has no dpop http header" in str(err.value).lower()

@pytest.mark.asyncio
async def test_verify_request_fail_multiple_dpop_proofs():
    """
    Test that requests with multiple DPoP proofs are rejected.
    """
    access_token = "test_token"
    dpop_proof1 = await generate_dpop_proof(
        access_token=access_token,
        http_method="GET",
        http_url="https://api.example.com/resource"
    )
    dpop_proof2 = await generate_dpop_proof(
        access_token=access_token,
        http_method="GET",
        http_url="https://api.example.com/resource"
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    with pytest.raises(InvalidDpopProofError) as err:
        await api_client.verify_request(
            headers={"authorization": f"DPoP {access_token}", "dpop": f"{dpop_proof1}, {dpop_proof2}"},  # Multiple proofs
            http_method="GET",
            http_url="https://api.example.com/resource"
        )

    assert "multiple" in str(err.value).lower()


