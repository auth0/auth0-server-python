from unittest.mock import ANY, AsyncMock, MagicMock

import httpx
import pytest
from jwcrypto import jwk as jwk_module

from auth0_server_python.auth_schemes.dpop_auth import DPoPAuth
from auth0_server_python.auth_server.my_account_client import MyAccountClient
from auth0_server_python.auth_types import (
    AuthenticationMethod,
    CompleteConnectAccountRequest,
    CompleteConnectAccountResponse,
    ConnectAccountRequest,
    ConnectAccountResponse,
    ConnectedAccount,
    ConnectedAccountConnection,
    ConnectParams,
    EnrollAuthenticationMethodRequest,
    EnrollmentChallengeResponse,
    GetFactorsResponse,
    ListAuthenticationMethodsResponse,
    ListConnectedAccountConnectionsResponse,
    ListConnectedAccountsResponse,
    PasskeyAuthResponse,
    UpdateAuthenticationMethodRequest,
    VerifyAuthenticationMethodRequest,
)
from auth0_server_python.error import (
    ApiError,
    InvalidArgumentError,
    MissingRequiredArgumentError,
    MyAccountApiError,
)


@pytest.mark.asyncio
async def test_connect_account_success(mocker):
    # Arrange
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 201
    response.json = MagicMock(return_value={
        "connect_uri": "https://auth0.local/connect",
        "auth_session": "<auth_session>",
        "connect_params": {"ticket": "<auth_ticket>"},
        "expires_in": 3600
    })

    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)
    request = ConnectAccountRequest(
        connection="<connection>",
        redirect_uri="<redirect_uri>",
        state="<state_xyz>",
        code_challenge="<code_challenge>",
        code_challenge_method="S256"
    )

    # Act
    result = await client.connect_account(access_token="<access_token>", request=request)

    # Assert
    mock_post.assert_awaited_with(
        url="https://auth0.local/me/v1/connected-accounts/connect",
        json={
            "connection": "<connection>",
            "redirect_uri": "<redirect_uri>",
            "state": "<state_xyz>",
            "code_challenge": "<code_challenge>",
            "code_challenge_method": "S256",
        },
        auth=ANY
    )
    assert result == ConnectAccountResponse(
        connect_uri="https://auth0.local/connect",
        auth_session="<auth_session>",
        connect_params=ConnectParams(ticket="<auth_ticket>"),
        expires_in=3600
    )

@pytest.mark.asyncio
async def test_connect_account_api_response_failure(mocker):
    # Arrange
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 401
    response.json = MagicMock(return_value={
        "title": "Invalid Token",
        "type": "https://auth0.com/api-errors/A0E-401-0003",
        "detail": "Invalid Token",
        "status": 401
    })

    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)
    request = ConnectAccountRequest(
        connection="<connection>",
        redirect_uri="<redirect_uri>",
        state="<state_xyz>",
        code_challenge="<code_challenge>",
        code_challenge_method="S256"
    )

    # Act

    with pytest.raises(MyAccountApiError) as exc:
        await client.connect_account(access_token="<access_token>", request=request)

    # Assert
    mock_post.assert_awaited_once()
    assert "Invalid Token" in str(exc.value)


@pytest.mark.asyncio
async def test_complete_connect_account_success(mocker):
    # Arrange
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 201
    response.json = MagicMock(return_value={
        "id": "<id>",
        "connection": "<connection>",
        "access_type": "<access_type>",
        "scopes": ["<some_scope>"],
        "created_at": "<created_at>",
    })

    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)
    request = CompleteConnectAccountRequest(
        auth_session="<auth_session>",
        connect_code="<connect_code>",
        redirect_uri="<redirect_uri>",
    )

    # Act
    result = await client.complete_connect_account(access_token="<access_token>", request=request)

    # Assert
    mock_post.assert_awaited_with(
        url="https://auth0.local/me/v1/connected-accounts/complete",
        json={
            "auth_session": "<auth_session>",
            "connect_code": "<connect_code>",
            "redirect_uri": "<redirect_uri>"
        },
        auth=ANY
    )
    assert result == CompleteConnectAccountResponse(
        id="<id>",
        connection="<connection>",
        access_type="<access_type>",
        scopes=["<some_scope>"],
        created_at="<created_at>",
    )

@pytest.mark.asyncio
async def test_complete_connect_account_api_response_failure(mocker):
    # Arrange
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 401
    response.json = MagicMock(return_value={
        "title": "Invalid Token",
        "type": "https://auth0.com/api-errors/A0E-401-0003",
        "detail": "Invalid Token",
        "status": 401
    })

    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)
    request = CompleteConnectAccountRequest(
        auth_session="<auth_session>",
        connect_code="<connect_code>",
        redirect_uri="<redirect_uri>",
    )

    # Act

    with pytest.raises(MyAccountApiError) as exc:
        await client.complete_connect_account(access_token="<access_token>", request=request)

    # Assert
    mock_post.assert_awaited_once()
    assert "Invalid Token" in str(exc.value)

@pytest.mark.asyncio
async def test_list_connected_accounts_success(mocker):
    # Arrange
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 200
    response.json = MagicMock(return_value={
        "accounts": [{
            "id": "<id_1>",
            "connection": "<connection>",
            "access_type": "offline",
            "scopes": ["openid", "profile", "email", "offline_access"],
            "created_at": "<created_at>",
            "expires_at": "<expires_at>"
        },
        {
            "id": "<id_2>",
            "connection": "<connection>",
            "access_type": "offline",
            "scopes": ["user:email", "foo", "bar"],
            "created_at": "<created_at>",
            "expires_at": "<expires_at>"
        }],
        "next": "<next_token>"
    })

    mock_get = mocker.patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=response)

    # Act
    result = await client.list_connected_accounts(
        access_token="<access_token>",
        connection="<connection>",
        from_param="<from_param>",
        take=2
    )

    # Assert
    mock_get.assert_awaited_with(
        url="https://auth0.local/me/v1/connected-accounts/accounts",
        params={
            "connection": "<connection>",
            "from": "<from_param>",
            "take": 2
        },
        auth=ANY
    )
    assert result == ListConnectedAccountsResponse(
        accounts=[ ConnectedAccount(
            id="<id_1>",
            connection="<connection>",
            access_type="offline",
            scopes=["openid", "profile", "email", "offline_access"],
            created_at="<created_at>",
            expires_at="<expires_at>"
        ), ConnectedAccount(
            id="<id_2>",
            connection="<connection>",
            access_type="offline",
            scopes=["user:email", "foo", "bar"],
            created_at="<created_at>",
            expires_at="<expires_at>"
        ) ],
        next="<next_token>"
    )

@pytest.mark.asyncio
async def test_list_connected_accounts_missing_access_token(mocker):
    # Arrange
    client = MyAccountClient(domain="auth0.local")
    mock_get = mocker.patch("httpx.AsyncClient.get", new_callable=AsyncMock)

    # Act
    with pytest.raises(MissingRequiredArgumentError) as exc:
        await client.list_connected_accounts(
        access_token=None,
        connection="<connection>",
        from_param="<from_param>",
        take=2
    )

    # Assert
    mock_get.assert_not_awaited()
    assert "access_token" in str(exc.value)

@pytest.mark.asyncio
@pytest.mark.parametrize("take", ["not_an_integer", 21.3, -5, 0])
async def test_list_connected_accounts_invalid_take_param(mocker, take):
    # Arrange
    client = MyAccountClient(domain="auth0.local")
    mock_get = mocker.patch("httpx.AsyncClient.get", new_callable=AsyncMock)

    # Act
    with pytest.raises(InvalidArgumentError) as exc:
        await client.list_connected_accounts(
        access_token="<access_token>",
        connection="<connection>",
        from_param="<from_param>",
        take=take
    )

    # Assert
    mock_get.assert_not_awaited()
    assert "The 'take' parameter must be a positive integer." in str(exc.value)

@pytest.mark.asyncio
async def test_list_connected_accounts_api_response_failure(mocker):
    # Arrange
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 401
    response.json = MagicMock(return_value={
        "title": "Invalid Token",
        "type": "https://auth0.com/api-errors/A0E-401-0003",
        "detail": "Invalid Token",
        "status": 401
    })

    mock_get = mocker.patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=response)

    # Act
    with pytest.raises(MyAccountApiError) as exc:
        await client.list_connected_accounts(
        access_token="<access_token>",
        connection="<connection>",
        from_param="<from_param>",
        take=2
    )

    # Assert
    mock_get.assert_awaited_once()
    assert "Invalid Token" in str(exc.value)

@pytest.mark.asyncio
async def test_delete_connected_account_success(mocker):
    # Arrange
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 204

    mock_get = mocker.patch("httpx.AsyncClient.delete", new_callable=AsyncMock, return_value=response)

    # Act
    await client.delete_connected_account(
        access_token="<access_token>",
        connected_account_id="<id_1>"
    )

    # Assert
    mock_get.assert_awaited_with(
        url="https://auth0.local/me/v1/connected-accounts/accounts/<id_1>",
        auth=ANY
    )

@pytest.mark.asyncio
async def test_delete_connected_account_missing_access_token(mocker):
    # Arrange
    client = MyAccountClient(domain="auth0.local")
    mock_delete = mocker.patch("httpx.AsyncClient.delete", new_callable=AsyncMock)

    # Act
    with pytest.raises(MissingRequiredArgumentError) as exc:
        await client.delete_connected_account(
            access_token=None,
            connected_account_id="<id_1>"
        )

    # Assert
    mock_delete.assert_not_awaited()
    assert "access_token" in str(exc.value)

@pytest.mark.asyncio
async def test_delete_connected_account_missing_connected_account_id(mocker):
    # Arrange
    client = MyAccountClient(domain="auth0.local")
    mock_delete = mocker.patch("httpx.AsyncClient.delete", new_callable=AsyncMock)

    # Act
    with pytest.raises(MissingRequiredArgumentError) as exc:
        await client.delete_connected_account(
            access_token="<access_token>",
            connected_account_id=None
        )

    # Assert
    mock_delete.assert_not_awaited()
    assert "connected_account_id" in str(exc.value)

@pytest.mark.asyncio
async def test_delete_connected_account_api_response_failure(mocker):
    # Arrange
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 401
    response.json = MagicMock(return_value={
        "title": "Invalid Token",
        "type": "https://auth0.com/api-errors/A0E-401-0003",
        "detail": "Invalid Token",
        "status": 401
    })

    mock_delete = mocker.patch("httpx.AsyncClient.delete", new_callable=AsyncMock, return_value=response)

    # Act
    with pytest.raises(MyAccountApiError) as exc:
        await client.delete_connected_account(
            access_token="<access_token>",
            connected_account_id="<id_1>"
        )

    # Assert
    mock_delete.assert_awaited_once()
    assert "Invalid Token" in str(exc.value)

@pytest.mark.asyncio
async def test_list_connected_account_connections_success(mocker):
    # Arrange
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 200
    response.json = MagicMock(return_value={
        "connections": [{
            "name": "github",
            "strategy": "github",
            "scopes": [
                "user:email"
            ]
        },
        {
            "name": "google-oauth2",
            "strategy": "google-oauth2",
            "scopes": [
                "email",
                "profile"
            ]
        }],
        "next": "<next_token>"
    })

    mock_get = mocker.patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=response)

    # Act
    result = await client.list_connected_account_connections(
        access_token="<access_token>",
        from_param="<from_param>",
        take=2
    )

    # Assert
    mock_get.assert_awaited_with(
        url="https://auth0.local/me/v1/connected-accounts/connections",
        params={
            "from": "<from_param>",
            "take": 2
        },
        auth=ANY
    )
    assert result == ListConnectedAccountConnectionsResponse(
        connections=[ ConnectedAccountConnection(
            name="github",
            strategy="github",
            scopes=["user:email"]
        ), ConnectedAccountConnection(
            name="google-oauth2",
            strategy="google-oauth2",
            scopes=["email", "profile"]
        ) ],
        next="<next_token>"
    )

@pytest.mark.asyncio
async def test_list_connected_account_connections_missing_access_token(mocker):
    # Arrange
    client = MyAccountClient(domain="auth0.local")
    mock_get = mocker.patch("httpx.AsyncClient.get", new_callable=AsyncMock)

    # Act
    with pytest.raises(MissingRequiredArgumentError) as exc:
        await client.list_connected_account_connections(
        access_token=None,
        from_param="<from_param>",
        take=2
    )

    # Assert
    mock_get.assert_not_awaited()
    assert "access_token" in str(exc.value)

@pytest.mark.asyncio
@pytest.mark.parametrize("take", ["not_an_integer", 21.3, -5, 0])
async def test_list_connected_account_connections_invalid_take_param(mocker, take):
    # Arrange
    client = MyAccountClient(domain="auth0.local")
    mock_get = mocker.patch("httpx.AsyncClient.get", new_callable=AsyncMock)

    # Act
    with pytest.raises(InvalidArgumentError) as exc:
        await client.list_connected_account_connections(
        access_token="<access_token>",
        from_param="<from_param>",
        take=take
    )

    # Assert
    mock_get.assert_not_awaited()
    assert "The 'take' parameter must be a positive integer." in str(exc.value)


@pytest.mark.asyncio
async def test_list_connected_account_connections_api_response_failure(mocker):
    # Arrange
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 401
    response.json = MagicMock(return_value={
        "title": "Invalid Token",
        "type": "https://auth0.com/api-errors/A0E-401-0003",
        "detail": "Invalid Token",
        "status": 401
    })

    mock_get = mocker.patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=response)

    # Act
    with pytest.raises(MyAccountApiError) as exc:
        await client.list_connected_account_connections(
        access_token="<access_token>",
        from_param="<from_param>",
        take=2
    )

    # Assert
    mock_get.assert_awaited_once()
    assert "Invalid Token" in str(exc.value)


# =============================================================================
# AUTHENTICATION METHODS & FACTORS (Passkey / MyAccount API)
# =============================================================================


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
    response.json = MagicMock(return_value={
        "title": "Forbidden",
        "type": "forbidden",
        "detail": "Insufficient scope",
        "status": 403,
    })
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
    response.json = MagicMock(return_value={
        "factors": [{"name": "webauthn-roaming", "enabled": True, "future_field": "value"}]
    })
    mocker.patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=response)

    result = await client.get_factors(access_token="token123")
    assert result.factors[0].name == "webauthn-roaming"


@pytest.mark.asyncio
async def test_list_authentication_methods_success(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 200
    response.json = MagicMock(return_value={
        "authentication_methods": [
            {"id": "am_1", "type": "passkey", "created_at": "2026-01-01T00:00:00Z", "key_id": "kid1"}
        ]
    })
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
    response.json = MagicMock(return_value={
        "id": "am_1", "type": "passkey", "created_at": "2026-01-01T00:00:00Z"
    })
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
    response.json = MagicMock(return_value={
        "id": "id/slash", "type": "passkey", "created_at": "2026-01-01T00:00:00Z"
    })
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
    response.json = MagicMock(return_value={
        "id": "passkey|new", "type": "passkey", "created_at": "2026-01-01T00:00:00Z"
    })
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
    response.json = MagicMock(return_value={
        "id": "am_1", "type": "passkey", "created_at": "2026-01-01T00:00:00Z", "name": "My Key",
    })
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
    response.status_code = 202
    response.headers = {"location": "/me/v1/authentication-methods/passkey|new"}
    response.json = MagicMock(return_value={
        "auth_session": "session_abc",
        "authn_params_public_key": {
            "challenge": "dGVzdA",
            "rp": {"id": "auth0.local", "name": "My App"},
            "user": {"id": "dXNlcl8x", "name": "user@test.com", "displayName": "Test User"},
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "authenticatorSelection": {"residentKey": "required", "userVerification": "preferred"},
            "timeout": 60000,
        },
    })
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
async def test_enroll_authentication_method_public_key_extra_fields_preserved(mocker):
    """Unknown WebAuthn fields (excludeCredentials, attestation, extensions) must not be dropped."""
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 202
    response.headers = {"location": "/me/v1/authentication-methods/passkey|new"}
    response.json = MagicMock(return_value={
        "auth_session": "session_abc",
        "authn_params_public_key": {
            "challenge": "dGVzdA",
            "rp": {"id": "auth0.local", "name": "My App"},
            "user": {"id": "dXNlcl8x", "name": "user@test.com"},
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "excludeCredentials": [{"type": "public-key", "id": "Y3JlZA"}],
            "attestation": "direct",
            "extensions": {"appid": "https://auth0.local"},
        },
    })
    mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

    req = EnrollAuthenticationMethodRequest(type="passkey")
    result = await client.enroll_authentication_method(access_token="token123", request=req)

    pk = result.authn_params_public_key
    assert pk.model_extra["excludeCredentials"] == [{"type": "public-key", "id": "Y3JlZA"}]
    assert pk.model_extra["attestation"] == "direct"
    assert pk.model_extra["extensions"] == {"appid": "https://auth0.local"}


@pytest.mark.asyncio
async def test_enroll_authentication_method_missing_location(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 202
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
    response.status_code = 202
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
    response.status_code = 202
    response.headers = {"location": "https://tenant.auth0.com/me/v1/authentication-methods/am_xyz"}
    response.json = MagicMock(return_value={"auth_session": "session_abc"})
    mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

    req = EnrollAuthenticationMethodRequest(type="passkey")
    result = await client.enroll_authentication_method(access_token="token123", request=req)
    assert result.authentication_method_id == "am_xyz"


@pytest.mark.asyncio
async def test_enroll_authentication_method_totp_preserves_secret(mocker):
    """TOTP enrollment response includes totp_secret and barcode_uri — must not be dropped."""
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 202
    response.headers = {"location": "/me/v1/authentication-methods/totp|new"}
    response.json = MagicMock(return_value={
        "auth_session": "session_totp",
        "totp_secret": "JBSWY3DPEHPK3PXP",
        "barcode_uri": "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP",
    })
    mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

    req = EnrollAuthenticationMethodRequest(type="totp")
    result = await client.enroll_authentication_method(access_token="token123", request=req)

    assert result.authentication_method_id == "totp|new"
    assert result.auth_session == "session_totp"
    assert result.model_extra["totp_secret"] == "JBSWY3DPEHPK3PXP"
    assert result.model_extra["barcode_uri"].startswith("otpauth://")


@pytest.mark.asyncio
async def test_enroll_authentication_method_oob_preserves_oob_code(mocker):
    """OOB (email/phone) enrollment response includes oob_code — must not be dropped."""
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 202
    response.headers = {"location": "/me/v1/authentication-methods/email|new"}
    response.json = MagicMock(return_value={
        "auth_session": "session_oob",
        "oob_code": "oob_abc123",
    })
    mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

    req = EnrollAuthenticationMethodRequest(type="email")
    result = await client.enroll_authentication_method(access_token="token123", request=req)

    assert result.authentication_method_id == "email|new"
    assert result.model_extra["oob_code"] == "oob_abc123"


@pytest.mark.asyncio
async def test_verify_authentication_method_success(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 201
    response.json = MagicMock(return_value={
        "id": "am_1", "type": "passkey", "created_at": "2026-01-01T00:00:00Z", "confirmed": True,
    })
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


def test_enrollment_challenge_response_repr():
    resp = EnrollmentChallengeResponse(
        authentication_method_id="am_1",
        auth_session="super_secret_session",
        authn_params_public_key=None,
    )
    repr_str = repr(resp)
    assert "super_secret_session" not in repr_str
    assert "[REDACTED]" in repr_str
    assert "am_1" in repr_str


def test_verify_request_auth_session_only_is_valid():
    req = VerifyAuthenticationMethodRequest(auth_session="session_abc")
    assert req.auth_session == "session_abc"
    assert req.otp_code is None
    assert req.authn_response is None


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


@pytest.mark.asyncio
async def test_list_authentication_methods_with_dpop_key(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 200
    response.json = MagicMock(return_value={"authentication_methods": []})
    mock_get = mocker.patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=response)

    dpop_key = jwk_module.JWK.generate(kty="EC", crv="P-256")
    await client.list_authentication_methods(access_token="token123", dpop_key=dpop_key)

    assert isinstance(mock_get.call_args[1]["auth"], DPoPAuth)


@pytest.mark.asyncio
async def test_get_authentication_method_with_dpop_key(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 200
    response.json = MagicMock(return_value={
        "id": "am_1", "type": "passkey", "created_at": "2026-01-01T00:00:00Z"
    })
    mock_get = mocker.patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=response)

    dpop_key = jwk_module.JWK.generate(kty="EC", crv="P-256")
    await client.get_authentication_method(
        access_token="token123", authentication_method_id="am_1", dpop_key=dpop_key
    )

    assert isinstance(mock_get.call_args[1]["auth"], DPoPAuth)


@pytest.mark.asyncio
async def test_delete_authentication_method_with_dpop_key(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 204
    mock_delete = mocker.patch(
        "httpx.AsyncClient.delete", new_callable=AsyncMock, return_value=response
    )

    dpop_key = jwk_module.JWK.generate(kty="EC", crv="P-256")
    await client.delete_authentication_method(
        access_token="token123", authentication_method_id="am_1", dpop_key=dpop_key
    )

    assert isinstance(mock_delete.call_args[1]["auth"], DPoPAuth)


@pytest.mark.asyncio
async def test_update_authentication_method_with_dpop_key(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 200
    response.json = MagicMock(return_value={
        "id": "am_1", "type": "passkey", "created_at": "2026-01-01T00:00:00Z"
    })
    mock_patch = mocker.patch(
        "httpx.AsyncClient.patch", new_callable=AsyncMock, return_value=response
    )

    dpop_key = jwk_module.JWK.generate(kty="EC", crv="P-256")
    req = UpdateAuthenticationMethodRequest(name="New Name")
    await client.update_authentication_method(
        access_token="token123", authentication_method_id="am_1", request=req, dpop_key=dpop_key
    )

    assert isinstance(mock_patch.call_args[1]["auth"], DPoPAuth)


@pytest.mark.asyncio
async def test_enroll_authentication_method_with_dpop_key(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 202
    response.headers = {"location": "/me/v1/authentication-methods/passkey|new"}
    response.json = MagicMock(return_value={"auth_session": "session_abc"})
    mock_post = mocker.patch(
        "httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response
    )

    dpop_key = jwk_module.JWK.generate(kty="EC", crv="P-256")
    req = EnrollAuthenticationMethodRequest(type="passkey")
    await client.enroll_authentication_method(
        access_token="token123", request=req, dpop_key=dpop_key
    )

    assert isinstance(mock_post.call_args[1]["auth"], DPoPAuth)


@pytest.mark.asyncio
async def test_verify_authentication_method_with_dpop_key(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 201
    response.json = MagicMock(return_value={
        "id": "am_1", "type": "passkey", "created_at": "2026-01-01T00:00:00Z"
    })
    mock_post = mocker.patch(
        "httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response
    )

    dpop_key = jwk_module.JWK.generate(kty="EC", crv="P-256")
    req = VerifyAuthenticationMethodRequest(auth_session="session_abc", otp_code="123456")
    await client.verify_authentication_method(
        access_token="token123",
        authentication_method_id="am_1",
        request=req,
        dpop_key=dpop_key,
    )

    assert isinstance(mock_post.call_args[1]["auth"], DPoPAuth)


@pytest.mark.asyncio
async def test_list_authentication_methods_api_error(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 403
    response.json = MagicMock(return_value={
        "title": "Forbidden", "type": "forbidden", "detail": "Insufficient scope", "status": 403,
    })
    mocker.patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=response)

    with pytest.raises(MyAccountApiError) as exc:
        await client.list_authentication_methods(access_token="token123")
    assert exc.value.status == 403


@pytest.mark.asyncio
async def test_list_authentication_methods_network_error(mocker):
    client = MyAccountClient(domain="auth0.local")
    mocker.patch(
        "httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=Exception("Connection refused")
    )

    with pytest.raises(ApiError):
        await client.list_authentication_methods(access_token="token123")


@pytest.mark.asyncio
async def test_get_authentication_method_api_error(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 404
    response.json = MagicMock(return_value={
        "title": "Not Found", "type": "not_found", "detail": "Not found", "status": 404,
    })
    mocker.patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=response)

    with pytest.raises(MyAccountApiError) as exc:
        await client.get_authentication_method(
            access_token="token123", authentication_method_id="am_1"
        )
    assert exc.value.status == 404


@pytest.mark.asyncio
async def test_get_authentication_method_network_error(mocker):
    client = MyAccountClient(domain="auth0.local")
    mocker.patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=Exception("timeout"))

    with pytest.raises(ApiError):
        await client.get_authentication_method(
            access_token="token123", authentication_method_id="am_1"
        )


@pytest.mark.asyncio
async def test_delete_authentication_method_api_error(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 404
    response.json = MagicMock(return_value={
        "title": "Not Found", "type": "not_found", "detail": "Not found", "status": 404,
    })
    mocker.patch("httpx.AsyncClient.delete", new_callable=AsyncMock, return_value=response)

    with pytest.raises(MyAccountApiError) as exc:
        await client.delete_authentication_method(
            access_token="token123", authentication_method_id="am_1"
        )
    assert exc.value.status == 404


@pytest.mark.asyncio
async def test_delete_authentication_method_network_error(mocker):
    client = MyAccountClient(domain="auth0.local")
    mocker.patch(
        "httpx.AsyncClient.delete",
        new_callable=AsyncMock,
        side_effect=Exception("Connection reset"),
    )

    with pytest.raises(ApiError):
        await client.delete_authentication_method(
            access_token="token123", authentication_method_id="am_1"
        )


@pytest.mark.asyncio
async def test_update_authentication_method_api_error(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 422
    response.json = MagicMock(return_value={
        "title": "Unprocessable", "type": "validation_error", "detail": "Invalid", "status": 422,
    })
    mocker.patch("httpx.AsyncClient.patch", new_callable=AsyncMock, return_value=response)

    req = UpdateAuthenticationMethodRequest(name="x")
    with pytest.raises(MyAccountApiError) as exc:
        await client.update_authentication_method(
            access_token="token123", authentication_method_id="am_1", request=req
        )
    assert exc.value.status == 422


@pytest.mark.asyncio
async def test_update_authentication_method_network_error(mocker):
    client = MyAccountClient(domain="auth0.local")
    mocker.patch(
        "httpx.AsyncClient.patch", new_callable=AsyncMock, side_effect=Exception("timeout")
    )

    req = UpdateAuthenticationMethodRequest(name="x")
    with pytest.raises(ApiError):
        await client.update_authentication_method(
            access_token="token123", authentication_method_id="am_1", request=req
        )


@pytest.mark.asyncio
async def test_enroll_authentication_method_api_error(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 403
    response.json = MagicMock(return_value={
        "title": "Forbidden", "type": "forbidden", "detail": "Scope missing", "status": 403,
    })
    mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

    req = EnrollAuthenticationMethodRequest(type="passkey")
    with pytest.raises(MyAccountApiError) as exc:
        await client.enroll_authentication_method(access_token="token123", request=req)
    assert exc.value.status == 403


@pytest.mark.asyncio
async def test_enroll_authentication_method_network_error(mocker):
    client = MyAccountClient(domain="auth0.local")
    mocker.patch(
        "httpx.AsyncClient.post",
        new_callable=AsyncMock,
        side_effect=Exception("Connection refused"),
    )

    req = EnrollAuthenticationMethodRequest(type="passkey")
    with pytest.raises(ApiError):
        await client.enroll_authentication_method(access_token="token123", request=req)


@pytest.mark.asyncio
async def test_verify_authentication_method_api_error(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 400
    response.json = MagicMock(return_value={
        "title": "Bad Request", "type": "invalid_request", "detail": "Invalid OTP", "status": 400,
    })
    mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

    req = VerifyAuthenticationMethodRequest(auth_session="session_abc", otp_code="000000")
    with pytest.raises(MyAccountApiError) as exc:
        await client.verify_authentication_method(
            access_token="token123", authentication_method_id="am_1", request=req
        )
    assert exc.value.status == 400


@pytest.mark.asyncio
async def test_verify_authentication_method_network_error(mocker):
    client = MyAccountClient(domain="auth0.local")
    mocker.patch(
        "httpx.AsyncClient.post",
        new_callable=AsyncMock,
        side_effect=Exception("Connection refused"),
    )

    req = VerifyAuthenticationMethodRequest(auth_session="session_abc", otp_code="123456")
    with pytest.raises(ApiError):
        await client.verify_authentication_method(
            access_token="token123", authentication_method_id="am_1", request=req
        )


@pytest.mark.asyncio
async def test_enroll_authentication_method_location_collection_url(mocker):
    client = MyAccountClient(domain="auth0.local")
    response = AsyncMock()
    response.status_code = 202
    response.headers = {"location": "/me/v1/authentication-methods/"}
    response.json = MagicMock(return_value={"auth_session": "session_abc"})
    mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

    req = EnrollAuthenticationMethodRequest(type="passkey")
    with pytest.raises(ApiError) as exc:
        await client.enroll_authentication_method(access_token="token123", request=req)
    assert "could not extract ID" in str(exc.value)


# =============================================================================
# DPoP nonce retry (RFC 9449 §8.2) — tests DPoPAuth.auth_flow directly
# =============================================================================


def test_dpop_auth_flow_retries_with_nonce_on_401():
    """
    DPoPAuth.auth_flow() must retry with DPoP-Nonce when server responds 401
    + DPoP-Nonce header (RFC 9449 §8.2). Tested by driving the generator directly.
    """
    import base64
    import json as _json

    dpop_key = jwk_module.JWK.generate(kty="EC", crv="P-256")
    auth = DPoPAuth(token="test_access_token", key=dpop_key)

    request = httpx.Request("GET", "https://auth0.local/me/v1/factors")
    flow = auth.auth_flow(request)

    # First yield — initial request
    first_request = next(flow)
    assert "DPoP" in first_request.headers
    assert "Authorization" in first_request.headers

    # First proof must not have nonce
    proof1 = first_request.headers["DPoP"]
    payload1_b64 = proof1.split(".")[1]
    padding = 4 - len(payload1_b64) % 4
    payload1 = _json.loads(base64.urlsafe_b64decode(payload1_b64 + "=" * padding))
    assert "nonce" not in payload1

    # Simulate 401 + DPoP-Nonce response
    nonce_response = httpx.Response(
        status_code=401,
        headers={"DPoP-Nonce": "server-nonce-abc"},
        content=b'{"error":"use_dpop_nonce"}',
        request=request,
    )

    # Second yield — retry request with nonce
    try:
        second_request = flow.send(nonce_response)
    except StopIteration:
        second_request = None

    assert second_request is not None
    proof2 = second_request.headers["DPoP"]
    payload2_b64 = proof2.split(".")[1]
    padding = 4 - len(payload2_b64) % 4
    payload2 = _json.loads(base64.urlsafe_b64decode(payload2_b64 + "=" * padding))
    assert payload2["nonce"] == "server-nonce-abc"


def test_dpop_auth_flow_no_retry_on_non_401():
    """DPoPAuth.auth_flow() must NOT retry when the response is not 401."""
    dpop_key = jwk_module.JWK.generate(kty="EC", crv="P-256")
    auth = DPoPAuth(token="test_access_token", key=dpop_key)

    request = httpx.Request("GET", "https://auth0.local/me/v1/factors")
    flow = auth.auth_flow(request)
    next(flow)

    success_response = httpx.Response(
        status_code=200,
        content=b'{"factors":[]}',
        request=request,
    )

    try:
        flow.send(success_response)
        retried = True
    except StopIteration:
        retried = False

    assert not retried

