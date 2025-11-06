from unittest.mock import ANY, AsyncMock, MagicMock

import pytest
from auth0_server_python.auth_server.my_account_client import MyAccountClient
from auth0_server_python.auth_types import (
    CompleteConnectAccountRequest,
    CompleteConnectAccountResponse,
    ConnectAccountRequest,
    ConnectAccountResponse,
    ConnectParams,
)
from auth0_server_python.error import MyAccountApiError


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
