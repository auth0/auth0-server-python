import pytest
from pytest_httpx import HTTPXMock
from unittest.mock import AsyncMock, patch

from src.api_client import ApiClient
from src.config import ApiClientOptions
from src.errors import MissingRequiredArgumentError, VerifyAccessTokenError, MissingRequiredArgumentError
from src.token_utils import generate_token


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
