from unittest.mock import AsyncMock, MagicMock

import pytest
from jwcrypto import jwk as jwk_module

from auth0_server_python.auth_schemes.dpop_auth import DPoPAuth
from auth0_server_python.auth_server.my_account_client import MyAccountClient
from auth0_server_python.auth_types import (
    AuthenticationMethod,
    EnrollAuthenticationMethodRequest,
    EnrollmentChallengeResponse,
    GetFactorsResponse,
    ListAuthenticationMethodsResponse,
    PasskeyAuthResponse,
    UpdateAuthenticationMethodRequest,
    VerifyAuthenticationMethodRequest,
)
from auth0_server_python.error import ApiError, MissingRequiredArgumentError, MyAccountApiError


@pytest.mark.asyncio
async def test_get_factors_success(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 200
    response.json = MagicMock(return_value={"factors": [{"name": "sms", "enabled": True}]})
    mocker.patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=response)

    result = await client.get_factors(access_token="token123")

    assert isinstance(result, GetFactorsResponse)
    assert len(result.factors) == 1
    assert result.factors[0].name == "sms"
    assert result.factors[0].enabled is True


@pytest.mark.asyncio
@pytest.mark.parametrize("access_token", [None, ""])
async def test_get_factors_missing_access_token(mocker, access_token):
    client = MyAccountClient(domain="auth0.local")
    mock_get = mocker.patch("httpx.AsyncClient.get", new_callable=AsyncMock)

    with pytest.raises(MissingRequiredArgumentError):
        await client.get_factors(access_token=access_token)

    mock_get.assert_not_awaited()


@pytest.mark.asyncio
async def test_get_factors_api_error(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 403
    response.json = MagicMock(
        return_value={
            "title": "Forbidden",
            "type": "forbidden",
            "detail": "Insufficient scope",
            "status": 403,
        }
    )
    mocker.patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=response)

    with pytest.raises(MyAccountApiError) as exc:
        await client.get_factors(access_token="token123")

    assert exc.value.status == 403


@pytest.mark.asyncio
async def test_get_factors_network_error(mocker):
    client = MyAccountClient(domain="auth0.local")
    mocker.patch(
        "httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=Exception("Connection refused")
    )

    with pytest.raises(ApiError):
        await client.get_factors(access_token="token123")


@pytest.mark.asyncio
async def test_get_factors_empty_list(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 200
    response.json = MagicMock(return_value={"factors": []})
    mocker.patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=response)

    result = await client.get_factors(access_token="token123")
    assert result.factors == []


@pytest.mark.asyncio
async def test_get_factors_extra_fields(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 200
    response.json = MagicMock(
        return_value={
            "factors": [{"name": "webauthn-roaming", "enabled": True, "future_field": "value"}]
        }
    )
    mocker.patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=response)

    result = await client.get_factors(access_token="token123")
    assert result.factors[0].name == "webauthn-roaming"


@pytest.mark.asyncio
async def test_list_authentication_methods_success(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 200
    response.json = MagicMock(
        return_value={
            "authentication_methods": [
                {
                    "id": "am_1",
                    "type": "passkey",
                    "created_at": "2026-01-01T00:00:00Z",
                    "key_id": "kid1",
                }
            ]
        }
    )
    mocker.patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=response)

    result = await client.list_authentication_methods(access_token="token123")
    assert isinstance(result, ListAuthenticationMethodsResponse)
    assert len(result.authentication_methods) == 1
    assert result.authentication_methods[0].type == "passkey"


@pytest.mark.asyncio
async def test_list_authentication_methods_with_type_filter(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 200
    response.json = MagicMock(return_value={"authentication_methods": []})
    mock_get = mocker.patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=response)

    await client.list_authentication_methods(access_token="token123", type_filter="passkey")
    mock_get.assert_awaited_once()
    call_kwargs = mock_get.call_args[1]
    assert call_kwargs["params"] == {"type": "passkey"}


@pytest.mark.asyncio
async def test_list_authentication_methods_empty(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 200
    response.json = MagicMock(return_value={"authentication_methods": []})
    mocker.patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=response)

    result = await client.list_authentication_methods(access_token="token123")
    assert result.authentication_methods == []


@pytest.mark.asyncio
async def test_get_authentication_method_success(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 200
    response.json = MagicMock(
        return_value={"id": "am_1", "type": "passkey", "created_at": "2026-01-01T00:00:00Z"}
    )
    mocker.patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=response)

    result = await client.get_authentication_method(
        access_token="token123", authentication_method_id="am_1"
    )
    assert isinstance(result, AuthenticationMethod)
    assert result.id == "am_1"


@pytest.mark.asyncio
@pytest.mark.parametrize("method_id", [None, ""])
async def test_get_authentication_method_missing_id(mocker, method_id):
    client = MyAccountClient(domain="auth0.local")
    mock_get = mocker.patch("httpx.AsyncClient.get", new_callable=AsyncMock)

    with pytest.raises(MissingRequiredArgumentError):
        await client.get_authentication_method(
            access_token="token123", authentication_method_id=method_id
        )

    mock_get.assert_not_awaited()


@pytest.mark.asyncio
async def test_get_authentication_method_path_traversal(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 200
    response.json = MagicMock(
        return_value={"id": "id/slash", "type": "passkey", "created_at": "2026-01-01T00:00:00Z"}
    )
    mock_get = mocker.patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=response)

    await client.get_authentication_method(
        access_token="token123", authentication_method_id="id/slash"
    )
    call_url = mock_get.call_args[1]["url"]
    assert "id%2Fslash" in call_url
    assert "id/slash" not in call_url.replace("https://auth0.local/me/", "")


@pytest.mark.asyncio
async def test_get_authentication_method_pipe_encoding(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 200
    response.json = MagicMock(
        return_value={"id": "passkey|new", "type": "passkey", "created_at": "2026-01-01T00:00:00Z"}
    )
    mock_get = mocker.patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=response)

    await client.get_authentication_method(
        access_token="token123", authentication_method_id="passkey|new"
    )
    call_url = mock_get.call_args[1]["url"]
    assert "passkey%7Cnew" in call_url


@pytest.mark.asyncio
async def test_delete_authentication_method_success(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 204
    mocker.patch("httpx.AsyncClient.delete", new_callable=AsyncMock, return_value=response)

    result = await client.delete_authentication_method(
        access_token="token123", authentication_method_id="am_1"
    )
    assert result is None


@pytest.mark.asyncio
@pytest.mark.parametrize("method_id", [None, ""])
async def test_delete_authentication_method_missing_id(mocker, method_id):
    client = MyAccountClient(domain="auth0.local")
    mock_delete = mocker.patch("httpx.AsyncClient.delete", new_callable=AsyncMock)

    with pytest.raises(MissingRequiredArgumentError):
        await client.delete_authentication_method(
            access_token="token123", authentication_method_id=method_id
        )

    mock_delete.assert_not_awaited()


@pytest.mark.asyncio
async def test_update_authentication_method_success(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 200
    response.json = MagicMock(
        return_value={
            "id": "am_1",
            "type": "passkey",
            "created_at": "2026-01-01T00:00:00Z",
            "name": "My Key",
        }
    )
    mock_patch = mocker.patch(
        "httpx.AsyncClient.patch", new_callable=AsyncMock, return_value=response
    )

    req = UpdateAuthenticationMethodRequest(name="My Key")
    result = await client.update_authentication_method(
        access_token="token123", authentication_method_id="am_1", request=req
    )
    assert result.name == "My Key"
    call_kwargs = mock_patch.call_args[1]
    assert call_kwargs["json"] == {"name": "My Key"}


@pytest.mark.asyncio
async def test_update_authentication_method_missing_request(mocker):
    client = MyAccountClient(domain="auth0.local")
    mocker.patch("httpx.AsyncClient.patch", new_callable=AsyncMock)

    with pytest.raises(MissingRequiredArgumentError):
        await client.update_authentication_method(
            access_token="token123", authentication_method_id="am_1", request=None
        )


@pytest.mark.asyncio
async def test_enroll_authentication_method_success(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 201
    response.headers = {"location": "/me/v1/authentication-methods/passkey|new"}
    response.json = MagicMock(
        return_value={
            "auth_session": "session_abc",
            "authn_params_public_key": {
                "challenge": "dGVzdA",
                "rp": {"id": "auth0.local", "name": "My App"},
                "user": {"id": "dXNlcl8x", "name": "user@test.com", "displayName": "Test User"},
                "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                "authenticatorSelection": {
                    "residentKey": "required",
                    "userVerification": "preferred",
                },
                "timeout": 60000,
            },
        }
    )
    mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

    req = EnrollAuthenticationMethodRequest(type="passkey")
    result = await client.enroll_authentication_method(access_token="token123", request=req)

    assert isinstance(result, EnrollmentChallengeResponse)
    assert result.authentication_method_id == "passkey|new"
    assert result.auth_session == "session_abc"
    assert result.authn_params_public_key is not None
    assert result.authn_params_public_key.pub_key_cred_params[0].alg == -7
    assert result.authn_params_public_key.authenticator_selection.resident_key == "required"
    assert result.authn_params_public_key.user.display_name == "Test User"


@pytest.mark.asyncio
async def test_enroll_authentication_method_missing_location(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 201
    response.headers = {}
    response.json = MagicMock(return_value={"auth_session": "session_abc"})
    mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

    req = EnrollAuthenticationMethodRequest(type="passkey")
    with pytest.raises(ApiError) as exc:
        await client.enroll_authentication_method(access_token="token123", request=req)

    assert "Location header" in str(exc.value)


@pytest.mark.asyncio
async def test_enroll_authentication_method_location_with_query(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 201
    response.headers = {"location": "/me/v1/authentication-methods/abc123?tracking=1"}
    response.json = MagicMock(return_value={"auth_session": "session_abc"})
    mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

    req = EnrollAuthenticationMethodRequest(type="passkey")
    result = await client.enroll_authentication_method(access_token="token123", request=req)
    assert result.authentication_method_id == "abc123"


@pytest.mark.asyncio
async def test_enroll_authentication_method_location_absolute_url(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 201
    response.headers = {"location": "https://tenant.auth0.com/me/v1/authentication-methods/am_xyz"}
    response.json = MagicMock(return_value={"auth_session": "session_abc"})
    mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

    req = EnrollAuthenticationMethodRequest(type="passkey")
    result = await client.enroll_authentication_method(access_token="token123", request=req)
    assert result.authentication_method_id == "am_xyz"


@pytest.mark.asyncio
async def test_verify_authentication_method_success(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 200
    response.json = MagicMock(
        return_value={
            "id": "am_1",
            "type": "passkey",
            "created_at": "2026-01-01T00:00:00Z",
            "confirmed": True,
        }
    )
    mock_post = mocker.patch(
        "httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response
    )

    authn_response = PasskeyAuthResponse(
        id="cred1",
        raw_id="cmF3MQ",
        type="public-key",
        authenticator_attachment="platform",
        response={"clientDataJSON": "abc", "attestationObject": "def"},
    )
    req = VerifyAuthenticationMethodRequest(
        auth_session="session_abc", authn_response=authn_response
    )
    result = await client.verify_authentication_method(
        access_token="token123", authentication_method_id="passkey|new", request=req
    )

    assert isinstance(result, AuthenticationMethod)
    assert result.confirmed is True

    call_kwargs = mock_post.call_args[1]
    body = call_kwargs["json"]
    assert "rawId" in body["authn_response"]
    assert "raw_id" not in body["authn_response"]
    assert "authenticatorAttachment" in body["authn_response"]
    assert body["auth_session"] == "session_abc"
    assert "passkey%7Cnew" in call_kwargs["url"]


@pytest.mark.asyncio
@pytest.mark.parametrize("method_id", [None, ""])
async def test_verify_authentication_method_missing_id(mocker, method_id):
    client = MyAccountClient(domain="auth0.local")
    mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)

    req = VerifyAuthenticationMethodRequest(auth_session="session_abc", otp_code="123456")
    with pytest.raises(MissingRequiredArgumentError):
        await client.verify_authentication_method(
            access_token="token123", authentication_method_id=method_id, request=req
        )


@pytest.mark.asyncio
async def test_enrollment_challenge_response_repr():
    resp = EnrollmentChallengeResponse(
        authentication_method_id="am_1",
        auth_session="super_secret_session",
        authn_params_public_key=None,
    )
    repr_str = repr(resp)
    assert "super_secret_session" not in repr_str
    assert "[REDACTED]" in repr_str
    assert "am_1" in repr_str


def test_verify_request_requires_at_least_one_method():
    with pytest.raises(Exception, match="At least one verification method"):
        VerifyAuthenticationMethodRequest(auth_session="session_abc")


def test_verify_request_accepts_otp_code():
    req = VerifyAuthenticationMethodRequest(auth_session="session_abc", otp_code="123456")
    assert req.otp_code == "123456"


def test_verify_request_accepts_authn_response():
    authn_resp = PasskeyAuthResponse(
        id="cred1",
        raw_id="cmF3MQ",
        type="public-key",
        response={"clientDataJSON": "abc", "attestationObject": "def"},
    )
    req = VerifyAuthenticationMethodRequest(auth_session="session_abc", authn_response=authn_resp)
    assert req.authn_response is not None


@pytest.mark.asyncio
async def test_get_factors_with_dpop_key(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 200
    response.json = MagicMock(return_value={"factors": [{"name": "sms", "enabled": True}]})
    mock_get = mocker.patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=response)

    dpop_key = jwk_module.JWK.generate(kty="EC", crv="P-256")
    await client.get_factors(access_token="token123", dpop_key=dpop_key)

    mock_get.assert_awaited_once()
    call_kwargs = mock_get.call_args[1]
    assert isinstance(call_kwargs["auth"], DPoPAuth)
