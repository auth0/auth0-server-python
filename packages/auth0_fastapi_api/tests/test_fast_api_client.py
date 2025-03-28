import pytest
from fastapi import FastAPI, Depends
from pytest_httpx import HTTPXMock
from fastapi.testclient import TestClient

from fastapi_plugin.fast_api_client import Auth0FastAPI
from fastapi_plugin.test_utils import generate_token 


@pytest.mark.asyncio
async def test_should_return_400_when_no_token():
    """
    should return 400 when no token
    """
    app = FastAPI()
    auth0 = Auth0FastAPI(domain="auth0.local", audience="<audience>")

    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth())):
        return "OK"

    client = TestClient(app)

    response = client.get("/test")
    assert response.status_code == 400
    json_body = response.json()
    assert json_body["detail"]["error"] == "invalid_request"
    assert json_body["detail"]["error_description"] == "No Authorization provided"


@pytest.mark.asyncio
async def test_should_return_200_when_valid_token(httpx_mock: HTTPXMock):
    """
    This time we mock OIDC discovery & JWKS calls so that our code sees valid data.

    1. We generate a legitimate token with a 'kid' that matches the JWKS we mock.
    2. We add responses for https://auth0.local/.well-known/openid-configuration and JWKS
       so that the plugin accepts the token as valid.
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
        audience="<audience>",
        issuer="https://auth0.local/",  # match the mocked OIDC discovery's issuer
        iat=True,
        exp=True
    )

    app = FastAPI()
    auth0 = Auth0FastAPI(domain="auth0.local", audience="<audience>")

    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth())):
        return "OK"

    client = TestClient(app)

    response = client.get(
        "/test",
        headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status_code == 200
    assert response.text == '"OK"'

@pytest.mark.asyncio
async def test_should_return_401_when_no_iss(httpx_mock: HTTPXMock):
    """
    2) Mocks OIDC & JWKS. Generates a token missing 'iss' (issuer=False).
       Expects a 401 from the plugin.
    """
    # 1) Mock endpoints
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

    # 2) Generate token missing 'iss' => issuer=False
    access_token = await generate_token(
        domain="auth0.local",
        user_id="user_123",
        audience="<audience>",
        issuer=False,  # no iss claim
        iat=True,
        exp=True
    )

    app = FastAPI()
    auth0 = Auth0FastAPI(domain="auth0.local", audience="<audience>")

    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth())):
        return "OK"

    client = TestClient(app)

    response = client.get(
        "/test",
        headers={"Authorization": f"Bearer {access_token}"}
    )

    # Typically we expect a 401 for 'missing iss' or something similar
    assert response.status_code == 401



@pytest.mark.asyncio
async def test_should_return_401_when_invalid_iss(httpx_mock: HTTPXMock):
    """
    3) Mocks OIDC & JWKS. The token sets a different issuer from the plugin's domain,
       we expect 401 'invalid issuer'.
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

    # Generate a token with an 'iss' that doesn't match "https://auth0.local/"
    access_token = await generate_token(
        domain="auth0.local",       # for the default if issuer=None, but we override below
        user_id="user_123",
        audience="<audience>",
        issuer="https://invalid-issuer.local",  # mismatch
        iat=True,
        exp=True
    )

    app = FastAPI()
    auth0 = Auth0FastAPI(domain="auth0.local", audience="<audience>")

    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth())):
        return "OK"

    client = TestClient(app)
    response = client.get("/test", headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 401



@pytest.mark.asyncio
async def test_should_return_401_when_no_exp(httpx_mock: HTTPXMock):
    """
    4) Mocks OIDC & JWKS, generates token with exp=False => no 'exp' claim. 
       The plugin or underlying code sees a missing 'exp' => 401.
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
        audience="<audience>",
        issuer="https://auth0.local/",
        iat=True,
        exp=False  # skip 'exp' claim
    )

    app = FastAPI()
    auth0 = Auth0FastAPI(domain="auth0.local", audience="<audience>")

    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth())):
        return "OK"

    client = TestClient(app)
    response = client.get("/test", headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_should_return_403_when_invalid_scope(httpx_mock: HTTPXMock):
    """
    5) Mocks OIDC & JWKS. The token includes scope="invalid", 
       but the plugin's route requires "valid" scope => 403 'insufficient_scope'.
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
        audience="<audience>",
        issuer="https://auth0.local/",
        iat=True,
        exp=True,
        claims={"scope": "invalid"}
    )

    app = FastAPI()
    auth0 = Auth0FastAPI(domain="auth0.local", audience="<audience>")

    @app.get("/test")
    async def test_route(claims=Depends(auth0.require_auth(scopes="valid"))):
        """
        The plugin or underlying code checks if 'valid' is in token's 'scope'.
        Since we only have 'invalid', expect 403 'insufficient_scope'.
        """
        return "OK"

    client = TestClient(app)
    response = client.get(
        "/test",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 403

