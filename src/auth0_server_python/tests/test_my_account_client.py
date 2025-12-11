from unittest.mock import ANY, AsyncMock, MagicMock

import pytest
from auth0_server_python.auth_server.my_account_client import MyAccountClient
from auth0_server_python.auth_types import (
    CompleteConnectAccountRequest,
    CompleteConnectAccountResponse,
    ConnectAccountRequest,
    ConnectAccountResponse,
    ConnectedAccount,
    ConnectedAccountConnection,
    ConnectParams,
    ListConnectedAccountConnectionsResponse,
    ListConnectedAccountResponse,
)
from auth0_server_python.error import (
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
    assert result == ListConnectedAccountResponse(
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

