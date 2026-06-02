import time
from unittest.mock import AsyncMock

import httpx
import pytest

from auth0_server_python.auth_server.server_client import ServerClient
from auth0_server_python.auth_types import (
    PasskeyAuthResponse,
    PasskeyLoginChallengeResponse,
    PasskeySignupChallengeResponse,
    PasskeyTokenResponse,
)
from auth0_server_python.error import ApiError, MissingRequiredArgumentError


@pytest.fixture
def server_client():
    return ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )


SIGNUP_CHALLENGE_RESPONSE = {
    "auth_session": "session_abc123",
    "authn_params_public_key": {
        "challenge": "dGVzdC1jaGFsbGVuZ2U",
        "rp": {"id": "auth0.local", "name": "Test App"},
        "user": {"id": "dXNlcl8x", "name": "user@example.com", "displayName": "Jane"},
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        "authenticatorSelection": {
            "residentKey": "required",
            "userVerification": "preferred",
        },
        "timeout": 60000,
    },
}

LOGIN_CHALLENGE_RESPONSE = {
    "auth_session": "session_login_xyz",
    "authn_params_public_key": {
        "challenge": "bG9naW4tY2hhbGxlbmdl",
        "rpId": "auth0.local",
        "timeout": 60000,
        "userVerification": "preferred",
    },
}

TOKEN_RESPONSE = {
    "access_token": "at_passkey_123",
    "id_token": "eyJ.test.jwt",
    "token_type": "Bearer",
    "expires_in": 86400,
    "scope": "openid profile",
}


def _mock_response(status_code=200, json_data=None, headers=None):
    resp = httpx.Response(
        status_code=status_code,
        json=json_data,
        headers=headers or {},
        request=httpx.Request("POST", "https://auth0.local/passkey/register"),
    )
    return resp


# =============================================================================
# passkey_signup_challenge
# =============================================================================


@pytest.mark.asyncio
async def test_passkey_signup_challenge_success(server_client, mocker):
    mock_response = _mock_response(200, SIGNUP_CHALLENGE_RESPONSE)
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mocker.patch.object(server_client, "_get_http_client", return_value=mock_client)

    result = await server_client.passkey_signup_challenge(
        email="user@example.com",
        name="Jane Doe",
        connection="Username-Password-Authentication",
    )

    assert isinstance(result, PasskeySignupChallengeResponse)
    assert result.auth_session == "session_abc123"
    assert result.authn_params_public_key.challenge == "dGVzdC1jaGFsbGVuZ2U"
    assert result.authn_params_public_key.rp.id == "auth0.local"
    assert result.authn_params_public_key.user.display_name == "Jane"
    assert result.authn_params_public_key.pub_key_cred_params[0].alg == -7
    assert result.authn_params_public_key.authenticator_selection.resident_key == "required"

    call_args = mock_client.post.call_args
    assert "/passkey/register" in call_args.args[0]
    body = call_args.kwargs["json"]
    assert body["client_id"] == "test_client_id"
    assert body["client_secret"] == "test_client_secret"
    assert body["user_profile"]["email"] == "user@example.com"
    assert body["user_profile"]["name"] == "Jane Doe"
    assert body["realm"] == "Username-Password-Authentication"


@pytest.mark.asyncio
async def test_passkey_signup_challenge_user_profile_fields(server_client, mocker):
    mock_response = _mock_response(200, SIGNUP_CHALLENGE_RESPONSE)
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mocker.patch.object(server_client, "_get_http_client", return_value=mock_client)

    await server_client.passkey_signup_challenge(
        email="u@e.com",
        username="jdoe",
        phone_number="+1234567890",
        given_name="Jane",
        family_name="Doe",
        nickname="jd",
        picture="https://example.com/pic.jpg",
        user_metadata={"role": "admin"},
        organization="org_123",
    )

    body = mock_client.post.call_args.kwargs["json"]
    assert body["user_profile"]["email"] == "u@e.com"
    assert body["user_profile"]["username"] == "jdoe"
    assert body["user_profile"]["phoneNumber"] == "+1234567890"
    assert body["user_profile"]["givenName"] == "Jane"
    assert body["user_profile"]["familyName"] == "Doe"
    assert body["user_profile"]["nickname"] == "jd"
    assert body["user_profile"]["picture"] == "https://example.com/pic.jpg"
    assert "user_metadata" not in body["user_profile"]
    assert body["userMetadata"] == {"role": "admin"}
    assert body["organization"] == "org_123"


@pytest.mark.asyncio
async def test_passkey_signup_challenge_minimal_body(server_client, mocker):
    mock_response = _mock_response(200, SIGNUP_CHALLENGE_RESPONSE)
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mocker.patch.object(server_client, "_get_http_client", return_value=mock_client)

    await server_client.passkey_signup_challenge()

    body = mock_client.post.call_args.kwargs["json"]
    assert body == {"client_id": "test_client_id", "client_secret": "test_client_secret"}
    assert "user_profile" not in body
    assert "realm" not in body
    assert "organization" not in body


@pytest.mark.asyncio
async def test_passkey_signup_challenge_api_error(server_client, mocker):
    error_resp = _mock_response(
        403,
        {"error": "access_denied", "error_description": "Passkey not enabled"},
    )
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=error_resp)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mocker.patch.object(server_client, "_get_http_client", return_value=mock_client)

    with pytest.raises(ApiError) as exc:
        await server_client.passkey_signup_challenge(email="test@example.com")
    assert "access_denied" in str(exc.value) or "Passkey not enabled" in str(exc.value)


@pytest.mark.asyncio
async def test_passkey_signup_challenge_non_json_error(server_client, mocker):
    resp = httpx.Response(
        status_code=502,
        content=b"<html>Bad Gateway</html>",
        headers={"content-type": "text/html"},
        request=httpx.Request("POST", "https://auth0.local/passkey/register"),
    )
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=resp)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mocker.patch.object(server_client, "_get_http_client", return_value=mock_client)

    with pytest.raises(ApiError) as exc:
        await server_client.passkey_signup_challenge()
    assert "502" in str(exc.value) or "passkey_challenge_error" in str(exc.value)


@pytest.mark.asyncio
async def test_passkey_signup_challenge_network_error(server_client, mocker):
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(side_effect=Exception("Connection refused"))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mocker.patch.object(server_client, "_get_http_client", return_value=mock_client)

    with pytest.raises(ApiError) as exc:
        await server_client.passkey_signup_challenge()
    assert "Passkey signup challenge failed" in str(exc.value)


# =============================================================================
# passkey_login_challenge
# =============================================================================


@pytest.mark.asyncio
async def test_passkey_login_challenge_success(server_client, mocker):
    mock_response = _mock_response(200, LOGIN_CHALLENGE_RESPONSE)
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mocker.patch.object(server_client, "_get_http_client", return_value=mock_client)

    result = await server_client.passkey_login_challenge(
        connection="Username-Password-Authentication",
        organization="org_abc",
    )

    assert isinstance(result, PasskeyLoginChallengeResponse)
    assert result.auth_session == "session_login_xyz"
    assert result.authn_params_public_key.challenge == "bG9naW4tY2hhbGxlbmdl"
    assert result.authn_params_public_key.rp_id == "auth0.local"
    assert result.authn_params_public_key.user_verification == "preferred"

    body = mock_client.post.call_args.kwargs["json"]
    assert body["client_id"] == "test_client_id"
    assert body["realm"] == "Username-Password-Authentication"
    assert body["organization"] == "org_abc"


@pytest.mark.asyncio
async def test_passkey_login_challenge_with_username(server_client, mocker):
    mock_response = _mock_response(200, LOGIN_CHALLENGE_RESPONSE)
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mocker.patch.object(server_client, "_get_http_client", return_value=mock_client)

    await server_client.passkey_login_challenge(username="jane@example.com")

    body = mock_client.post.call_args.kwargs["json"]
    assert body["username"] == "jane@example.com"


@pytest.mark.asyncio
async def test_passkey_login_challenge_api_error(server_client, mocker):
    error_resp = _mock_response(
        400,
        {"error": "invalid_request", "error_description": "Missing client_id"},
    )
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=error_resp)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mocker.patch.object(server_client, "_get_http_client", return_value=mock_client)

    with pytest.raises(ApiError):
        await server_client.passkey_login_challenge()


@pytest.mark.asyncio
async def test_passkey_login_challenge_network_error(server_client, mocker):
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(side_effect=Exception("timeout"))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mocker.patch.object(server_client, "_get_http_client", return_value=mock_client)

    with pytest.raises(ApiError):
        await server_client.passkey_login_challenge()


# =============================================================================
# signin_with_passkey
# =============================================================================


@pytest.fixture
def authn_response():
    return PasskeyAuthResponse(
        id="cred_abc123",
        raw_id="Y3JlZF9hYmMxMjM",
        type="public-key",
        authenticator_attachment="platform",
        response={
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
            "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2M",
            "signature": "MEUCIQC",
            "userHandle": "dXNlcl8x",
        },
    )


@pytest.mark.asyncio
async def test_signin_with_passkey_success(server_client, authn_response, mocker):
    mock_response = _mock_response(200, TOKEN_RESPONSE)
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mocker.patch.object(server_client, "_get_http_client", return_value=mock_client)
    mocker.patch.object(
        server_client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/oauth/token"},
    )

    result = await server_client.signin_with_passkey(
        auth_session="session_xyz",
        authn_response=authn_response,
        scope="openid profile",
        audience="https://api.example.com",
        connection="Username-Password-Authentication",
        organization="org_abc",
    )

    assert isinstance(result, PasskeyTokenResponse)
    assert result.access_token == "at_passkey_123"
    assert result.token_type == "Bearer"
    assert abs(result.expires_at - (int(time.time()) + 86400)) <= 2

    body = mock_client.post.call_args.kwargs["json"]
    assert body["grant_type"] == "urn:okta:params:oauth:grant-type:webauthn"
    assert body["client_id"] == "test_client_id"
    assert body["client_secret"] == "test_client_secret"
    assert body["auth_session"] == "session_xyz"
    assert body["scope"] == "openid profile"
    assert body["audience"] == "https://api.example.com"
    assert body["realm"] == "Username-Password-Authentication"
    assert body["organization"] == "org_abc"
    assert body["authn_response"]["rawId"] == "Y3JlZF9hYmMxMjM"
    assert body["authn_response"]["authenticatorAttachment"] == "platform"
    assert "raw_id" not in body["authn_response"]


@pytest.mark.asyncio
async def test_signin_with_passkey_uses_json_content_type(server_client, authn_response, mocker):
    mock_response = _mock_response(200, TOKEN_RESPONSE)
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mocker.patch.object(server_client, "_get_http_client", return_value=mock_client)
    mocker.patch.object(
        server_client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/oauth/token"},
    )

    await server_client.signin_with_passkey(
        auth_session="s",
        authn_response=authn_response,
    )

    call_kwargs = mock_client.post.call_args.kwargs
    assert "json" in call_kwargs
    assert "data" not in call_kwargs


@pytest.mark.asyncio
@pytest.mark.parametrize("auth_session", [None, ""])
async def test_signin_with_passkey_missing_auth_session(
    server_client, authn_response, auth_session
):
    with pytest.raises(MissingRequiredArgumentError):
        await server_client.signin_with_passkey(
            auth_session=auth_session,
            authn_response=authn_response,
        )


@pytest.mark.asyncio
async def test_signin_with_passkey_missing_authn_response(server_client):
    with pytest.raises(MissingRequiredArgumentError):
        await server_client.signin_with_passkey(
            auth_session="session_abc",
            authn_response=None,
        )


@pytest.mark.asyncio
async def test_signin_with_passkey_api_error(server_client, authn_response, mocker):
    error_resp = _mock_response(
        401,
        {"error": "invalid_grant", "error_description": "Invalid auth_session"},
    )
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=error_resp)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mocker.patch.object(server_client, "_get_http_client", return_value=mock_client)
    mocker.patch.object(
        server_client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/oauth/token"},
    )

    with pytest.raises(ApiError) as exc:
        await server_client.signin_with_passkey(
            auth_session="expired_session",
            authn_response=authn_response,
        )
    assert "invalid_grant" in str(exc.value) or "Invalid auth_session" in str(exc.value)


@pytest.mark.asyncio
async def test_signin_with_passkey_missing_token_endpoint(server_client, authn_response, mocker):
    mocker.patch.object(
        server_client,
        "_get_oidc_metadata_cached",
        return_value={},
    )

    with pytest.raises(ApiError) as exc:
        await server_client.signin_with_passkey(
            auth_session="session",
            authn_response=authn_response,
        )
    assert "token endpoint" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_signin_with_passkey_network_error(server_client, authn_response, mocker):
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(side_effect=Exception("Connection reset"))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mocker.patch.object(server_client, "_get_http_client", return_value=mock_client)
    mocker.patch.object(
        server_client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/oauth/token"},
    )

    with pytest.raises(ApiError):
        await server_client.signin_with_passkey(
            auth_session="session",
            authn_response=authn_response,
        )


@pytest.mark.asyncio
async def test_signin_with_passkey_no_client_secret(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="public_client",
        client_secret=None,
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret",
    )

    mock_response = _mock_response(200, TOKEN_RESPONSE)
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mocker.patch.object(client, "_get_http_client", return_value=mock_client)
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/oauth/token"},
    )

    authn_resp = PasskeyAuthResponse(
        id="cred",
        raw_id="cmF3",
        type="public-key",
        response={"clientDataJSON": "abc", "authenticatorData": "def", "signature": "ghi"},
    )

    await client.signin_with_passkey(
        auth_session="session",
        authn_response=authn_resp,
    )

    body = mock_client.post.call_args.kwargs["json"]
    assert "client_secret" not in body
    assert body["client_id"] == "public_client"


@pytest.mark.asyncio
async def test_signup_challenge_repr_redacts_auth_session():
    resp = PasskeySignupChallengeResponse.model_validate(SIGNUP_CHALLENGE_RESPONSE)
    repr_str = repr(resp)
    assert "session_abc123" not in repr_str
    assert "[REDACTED]" in repr_str


@pytest.mark.asyncio
async def test_login_challenge_repr_redacts_auth_session():
    resp = PasskeyLoginChallengeResponse.model_validate(LOGIN_CHALLENGE_RESPONSE)
    repr_str = repr(resp)
    assert "session_login_xyz" not in repr_str
    assert "[REDACTED]" in repr_str


def test_passkey_token_response_repr_redacts_tokens():
    resp = PasskeyTokenResponse(
        access_token="secret_at_value",
        token_type="Bearer",
        expires_in=86400,
        id_token="secret_id_token",
        refresh_token="secret_rt_value",
    )
    repr_str = repr(resp)
    assert "secret_at_value" not in repr_str
    assert "secret_id_token" not in repr_str
    assert "secret_rt_value" not in repr_str
    assert "[REDACTED]" in repr_str
    assert "86400" in repr_str


# =============================================================================
# expires_at edge cases
# =============================================================================


@pytest.mark.asyncio
async def test_signin_with_passkey_preserves_server_expires_at(
    server_client, authn_response, mocker
):
    token_data = {
        "access_token": "at_123",
        "token_type": "Bearer",
        "expires_in": 3600,
        "expires_at": 9999999999,
    }
    mock_response = _mock_response(200, token_data)
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mocker.patch.object(server_client, "_get_http_client", return_value=mock_client)
    mocker.patch.object(
        server_client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/oauth/token"},
    )

    result = await server_client.signin_with_passkey(
        auth_session="session", authn_response=authn_response
    )

    assert result.expires_at == 9999999999


@pytest.mark.asyncio
async def test_signin_with_passkey_missing_expires_at_calculates(
    server_client, authn_response, mocker
):
    token_data = {
        "access_token": "at_123",
        "token_type": "Bearer",
        "expires_in": 60,
    }
    mock_response = _mock_response(200, token_data)
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mocker.patch.object(server_client, "_get_http_client", return_value=mock_client)
    mocker.patch.object(
        server_client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/oauth/token"},
    )

    result = await server_client.signin_with_passkey(
        auth_session="session", authn_response=authn_response
    )

    assert abs(result.expires_at - (int(time.time()) + 60)) <= 2
