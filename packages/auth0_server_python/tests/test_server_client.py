import pytest
import time
import asyncio
from unittest.mock import AsyncMock, patch

# Adjust import to match your actual package structure
from auth_server.server_client import ServerClient
from error import MissingRequiredArgumentError, ApiError, MissingTransactionError, StartLinkUserError, AccessTokenForConnectionError,BackchannelLogoutError


@pytest.mark.asyncio
async def test_init_no_secret_raises():
    """
    If 'secret' is not provided, ServerClient should raise MissingRequiredArgumentError.
    """
    with pytest.raises(MissingRequiredArgumentError) as exc:
        _ = ServerClient(
            domain="example.auth0.com",
            client_id="client_id",
            client_secret="client_secret",
        )
    assert "secret" in str(exc.value)


@pytest.mark.asyncio
async def test_start_interactive_login_no_redirect_uri():
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="some-secret"
    )
    with pytest.raises(MissingRequiredArgumentError) as exc:
        await client.start_interactive_login()
    # Check the error message
    assert "redirect_uri" in str(exc.value)

@pytest.mark.asyncio
async def test_start_interactive_login_builds_auth_url(mocker):
    # Setup
    mock_transaction_store = AsyncMock()
    mock_state_store = AsyncMock()
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        state_store=mock_state_store,
        transaction_store=mock_transaction_store,
        secret="some-secret",
        authorization_params={"redirect_uri": "/test_redirect_uri"}
    )

    # Mock out HTTP calls or the internal methods that create the auth URL
    mocker.patch.object(
        client, 
        "_fetch_oidc_metadata", 
        return_value={"authorization_endpoint": "https://auth0.local/authorize"}
    )
    mock_oauth = mocker.patch.object(
        client._oauth, 
        "create_authorization_url", 
        return_value=("https://auth0.local/authorize?client_id=<client_id>&redirect_uri=/test_redirect_uri", "some_state")
    )

    # Act
    url = await client.start_interactive_login()

    # Assert
    assert url == "https://auth0.local/authorize?client_id=<client_id>&redirect_uri=/test_redirect_uri"
    mock_transaction_store.set.assert_awaited()
    mock_oauth.assert_called_once()


@pytest.mark.asyncio
async def test_complete_interactive_login_no_transaction():
    mock_transaction_store = AsyncMock()
    mock_transaction_store.get.return_value = None  # no transaction

    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        state_store=AsyncMock(),
        transaction_store=mock_transaction_store,
        secret="some-secret"
    )

    callback_url = "https://auth0.local/callback?code=123&state=abc"

    with pytest.raises(MissingTransactionError) as exc:
        await client.complete_interactive_login(callback_url)

    assert "transaction" in str(exc.value)

# @pytest.mark.asyncio
# async def test_complete_interactive_login_returns_app_state(mocker):
#     mock_tx_store = AsyncMock()
#     # The stored transaction includes an appState
#     mock_tx_store.get.return_value = {"appState": {"foo": "bar"}, "code_verifier": "123"}

#     mock_state_store = AsyncMock()

#     client = ServerClient(
#         domain="auth0.local",
#         client_id="client_id",
#         client_secret="client_secret",
#         transaction_store=mock_tx_store,
#         state_store=mock_state_store,
#         secret="some-secret",
#     )

#     # Patch token exchange
#     mocker.patch.object(client._oauth, "metadata", {"token_endpoint": "https://auth0.local/token"})
#     mock_fetch_token = mocker.patch.object(client._oauth, "fetch_token", return_value={
#         "access_token": "token123",
#         "expires_in": 3600,
#         "userinfo": {"sub": "user123"},
#     })

#     result = await client.complete_interactive_login("https://myapp.com/callback?code=abc")
#     assert result["app_state"] == {"foo": "bar"}

#     # Check the store was updated
#     mock_state_store.set.assert_awaited_once()
#     mock_tx_store.delete.assert_awaited_once()


@pytest.mark.asyncio
async def test_login_backchannel_stores_access_token(mocker):
    mock_transaction_store = AsyncMock()
    mock_state_store = AsyncMock()

    mock_state_store.get.return_value = {
        "token_sets": []  # or any pre-existing tokens you want
    }

    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        transaction_store=mock_transaction_store,
        state_store=mock_state_store,
        secret="some-secret"
    )

    # --- Patch the entire method used by login_backchannel. ---
    mocker.patch.object(
        client, 
        "backchannel_authentication",
        return_value={
            "access_token": "access_token_value",
            "expires_in": 3600,
            # any other fields your code expects
        }
    )

    # Act: call login_backchannel, which under the hood normally calls
    # backchannel_authentication, but now we’ve mocked that method.
    await client.login_backchannel({
        # your test options here
    })

    # Assert that the new token was stored
    mock_state_store.set.assert_awaited()

    # Check what was stored
    call_args = mock_state_store.set.call_args
    args, kwargs = call_args
    stored_key = args[0]
    stored_value = args[1]

    assert stored_key == client._state_identifier
    # The structure might vary, but typically you have a list/dict representing the new token
    assert "token_sets" in stored_value
    assert stored_value["token_sets"][0]["access_token"] == "access_token_value"


@pytest.mark.asyncio
async def test_start_link_user_no_id_token():
    mock_transaction_store = AsyncMock()
    mock_state_store = AsyncMock()
    # mock_state_store.get.return_value = {} or None => means no user, no idToken
    
    server_client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        transaction_store=mock_transaction_store,
        state_store=mock_state_store,
        secret="some-secret"
    )
    
    # No 'idToken' in the store
    mock_state_store.get.return_value = None
    
    with pytest.raises(StartLinkUserError) as exc:
        await server_client.start_link_user({
            "connection": "<connection>"
        })
    assert "Unable to start the user linking process without a logged in user" in str(exc.value)

@pytest.mark.asyncio
async def test_start_link_user_no_id_token():
    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = None  # No session => no idToken

    client = ServerClient(
        domain="auth0.local",
        client_id="client_id",
        client_secret="client_secret",
        transaction_store=AsyncMock(),
        state_store=mock_state_store,
        secret="some-secret",
    )

    with pytest.raises(StartLinkUserError) as exc:
        await client.start_link_user({"connection": "some_connection"})
    assert "Unable to start the user linking process without a logged in user" in str(exc.value)

# @pytest.mark.asyncio
# async def test_complete_link_user_returns_app_state(mocker):
#     mock_tx_store = AsyncMock()
#     mock_tx_store.get.return_value = {
#         "app_state": {"foo": "bar"},
#         "code_verifier": "abc"
#     }

#     mock_state_store = AsyncMock()
#     client = ServerClient(
#         domain="auth0.local",
#         client_id="client_id",
#         client_secret="client_secret",
#         transaction_store=mock_tx_store,
#         state_store=mock_state_store,
#         secret="some-secret",
#     )

#     # Patch token exchange
#     mocker.patch.object(client._oauth, "metadata", {"token_endpoint": "https://auth0.local/token"})
#     mocker.patch.object(client._oauth, "fetch_token", return_value={"access_token": "token123"})

#     result = await client.complete_link_user("https://myapp.com/callback?code=123")
#     assert result["app_state"] == {"foo": "bar"}
#     mock_tx_store.delete.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_user_in_store():
    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = {"user": {"sub": "user123"}}

    client = ServerClient(
        domain="auth0.local",
        client_id="client_id",
        client_secret="client_secret",
        transaction_store=AsyncMock(),
        state_store=mock_state_store,
        secret="some-secret"
    )

    user = await client.get_user()
    assert user == {"sub": "user123"}


@pytest.mark.asyncio
async def test_get_user_none():
    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = None

    client = ServerClient(
        domain="auth0.local",
        client_id="client_id",
        client_secret="client_secret",
        transaction_store=AsyncMock(),
        state_store=mock_state_store,
        secret="some-secret"
    )

    user = await client.get_user()
    assert user is None

@pytest.mark.asyncio
async def test_get_session_ok():
    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = {
        "user": {"sub": "user123"},
        "id_token": "token123",
        "internal": {"sid": "some_sid"},
    }

    client = ServerClient(
        domain="auth0.local",
        client_id="client_id",
        client_secret="client_secret",
        transaction_store=AsyncMock(),
        state_store=mock_state_store,
        secret="some-secret"
    )

    session_data = await client.get_session()
    assert session_data["user"] == {"sub": "user123"}
    assert session_data["id_token"] == "token123"
    assert "internal" not in session_data  # if your code filters that out

@pytest.mark.asyncio
async def test_get_session_none():
    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = None

    client = ServerClient(
        domain="auth0.local",
        client_id="client_id",
        client_secret="client_secret",
        transaction_store=AsyncMock(),
        state_store=mock_state_store,
        secret="some-secret"
    )

    session_data = await client.get_session()
    assert session_data is None

@pytest.mark.asyncio
async def test_get_access_token_from_store():
    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = {
        "refresh_token": None,
        "token_sets": [
            {
                "audience": "default",
                "access_token": "token_from_store",
                "expires_at": int(time.time()) + 500
            }
        ]
    }

    client = ServerClient(
        domain="auth0.local",
        client_id="client_id",
        client_secret="client_secret",
        transaction_store=AsyncMock(),
        state_store=mock_state_store,
        secret="some-secret"
    )

    token = await client.get_access_token()
    assert token == "token_from_store"

@pytest.mark.asyncio
async def test_get_access_token_refresh_expired(mocker):
    mock_state_store = AsyncMock()
    # expired token
    mock_state_store.get.return_value = {
        "refresh_token": "refresh_xyz",
        "token_sets": [
            {
                "audience": "default",
                "access_token": "expired_token",
                "expires_at": int(time.time()) - 500
            }
        ]
    }

    client = ServerClient(
        domain="auth0.local",
        client_id="client_id",
        client_secret="client_secret",
        transaction_store=AsyncMock(),
        state_store=mock_state_store,
        secret="some-secret"
    )

    # Patch method that does the refresh call
    mocker.patch.object(client, "get_token_by_refresh_token", return_value={
        "access_token": "new_token",
        "expires_in": 3600
    })

    token = await client.get_access_token()
    assert token == "new_token"
    mock_state_store.set.assert_awaited_once()

@pytest.mark.asyncio
async def test_get_access_token_for_connection_cached():
    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = {
        "refresh_token": None,
        "connection_token_sets": [
            {
                "connection": "my_connection",
                "access_token": "cached_conn_token",
                "expires_at": int(time.time()) + 500
            }
        ]
    }

    client = ServerClient(
        domain="auth0.local",
        client_id="client_id",
        client_secret="client_secret",
        state_store=mock_state_store,
        secret="some-secret"
    )
    token = await client.get_access_token_for_connection({"connection": "my_connection"})
    assert token == "cached_conn_token"

@pytest.mark.asyncio
async def test_get_access_token_for_connection_no_refresh():
    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = {
        "refresh_token": "",
        "connection_token_sets": []
    }

    client = ServerClient(
        domain="auth0.local",
        client_id="client_id",
        client_secret="client_secret",
        state_store=mock_state_store,
        secret="some-secret"
    )
    with pytest.raises(AccessTokenForConnectionError) as exc:
        await client.get_access_token_for_connection({"connection": "my_connection"})
    assert "A refresh token was not found" in str(exc.value)

@pytest.mark.asyncio
async def test_logout():
    mock_state_store = AsyncMock()

    client = ServerClient(
        domain="auth0.local",
        client_id="client_id",
        client_secret="client_secret",
        state_store=mock_state_store,
        secret="some-secret"
    )
    url = await client.logout({"return_to": "/after_logout"})

    mock_state_store.delete.assert_awaited_once()
    # Check returned URL
    assert "auth0.local/v2/logout" in url
    assert "client_id=" in url
    assert "returnTo=%2Fafter_logout" in url

@pytest.mark.asyncio
async def test_logout_no_session():
    mock_state_store = AsyncMock()

    client = ServerClient(
        domain="auth0.local",
        client_id="client_id",
        client_secret="client_secret",
        state_store=mock_state_store,
        secret="some-secret"
    )
    mock_state_store.delete.side_effect = None  # Even if it's empty

    url = await client.logout({"return_to": "/bye"})

    mock_state_store.delete.assert_awaited_once()  # No error if already empty
    assert "logout" in url

@pytest.mark.asyncio
async def test_handle_backchannel_logout_no_token():
    client = ServerClient(
        domain="auth0.local",
        client_id="client_id",
        client_secret="client_secret",
        secret="some-secret"
    )

    with pytest.raises(BackchannelLogoutError) as exc:
        await client.handle_backchannel_logout("")
    assert "Missing logout token" in str(exc.value)

@pytest.mark.asyncio
async def test_handle_backchannel_logout_ok(mocker):
    mock_state_store = AsyncMock()
    client = ServerClient(
        domain="auth0.local",
        client_id="client_id",
        client_secret="client_secret",
        state_store=mock_state_store,
        secret="some-secret"
    )

    mock_jwt_decode = mocker.patch("jwt.decode", return_value={
        "events": {"http://schemas.openid.net/event/backchannel-logout": {}},
        "sub": "user_sub",
        "sid": "session_id_123"
    })

    await client.handle_backchannel_logout("some_logout_token")
    mock_state_store.delete_by_logout_token.assert_awaited_once_with(
        {"sub": "user_sub", "sid": "session_id_123"}, 
        None
    )

