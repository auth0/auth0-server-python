import json
import time
from unittest.mock import ANY, AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from auth0_server_python.auth_server.my_account_client import MyAccountClient
from auth0_server_python.auth_server.server_client import ServerClient
from auth0_server_python.auth_types import (
    CompleteConnectAccountRequest,
    ConnectAccountOptions,
    ConnectAccountRequest,
    ConnectAccountResponse,
    ConnectParams,
    DomainResolverContext,
    LogoutOptions,
    StateData,
    TransactionData,
)
from auth0_server_python.error import (
    AccessTokenForConnectionError,
    ApiError,
    BackchannelLogoutError,
    ConfigurationError,
    DomainResolverError,
    MissingRequiredArgumentError,
    MissingTransactionError,
    PollingApiError,
    StartLinkUserError,
)
from auth0_server_python.utils import PKCE


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
async def test_start_interactive_login_no_redirect_uri(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="some-secret"
    )
    
    # Mock OIDC metadata fetch
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"issuer": "https://auth0.local/", "authorization_endpoint": "https://auth0.local/authorize"}
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
        "_get_oidc_metadata_cached",
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

@pytest.mark.asyncio
async def test_complete_interactive_login_returns_app_state(mocker):
    mock_tx_store = AsyncMock()
    # The stored transaction includes an appState with origin_domain and origin_issuer
    mock_tx_store.get.return_value = TransactionData(
        code_verifier="123", 
        app_state={"foo": "bar"},
        origin_domain="auth0.local",
        origin_issuer="https://auth0.local/"
    )

    mock_state_store = AsyncMock()

    client = ServerClient(
        domain="auth0.local",
        client_id="client_id",
        client_secret="client_secret",
        transaction_store=mock_tx_store,
        state_store=mock_state_store,
        secret="some-secret",
    )

    # Mock OIDC metadata fetch
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"issuer": "https://auth0.local/", "token_endpoint": "https://auth0.local/token"}
    )

    # Patch token exchange
    mocker.patch.object(client._oauth, "metadata", {"token_endpoint": "https://auth0.local/token"})

    async_fetch_token = AsyncMock()
    async_fetch_token.return_value = {
        "access_token": "token123",
        "expires_in": 3600,
        "userinfo": {"sub": "user123"},
    }
    mocker.patch.object(client._oauth, "fetch_token", async_fetch_token)


    result = await client.complete_interactive_login("https://myapp.com/callback?code=abc&state=xyz")

    assert result["app_state"] == {"foo": "bar"}
    mock_state_store.set.assert_awaited_once()
    mock_tx_store.delete.assert_awaited_once()

@pytest.mark.asyncio
async def test_start_link_user_no_id_token():
    mock_transaction_store = AsyncMock()
    mock_state_store = AsyncMock()

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
async def test_start_link_user_no_session():
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

@pytest.mark.asyncio
async def test_complete_link_user_returns_app_state(mocker):
    mock_tx_store = AsyncMock()
    mock_tx_store.get.return_value = TransactionData(code_verifier="abc", app_state={"foo": "bar"})

    mock_state_store = AsyncMock()
    client = ServerClient(
        domain="auth0.local",
        client_id="client_id",
        client_secret="client_secret",
        transaction_store=mock_tx_store,
        state_store=mock_state_store,
        secret="some-secret",
    )

    # Patch token exchange
    mocker.patch.object(client, "_get_oidc_metadata_cached", return_value={"token_endpoint": "https://auth0.local/token"})
    async_fetch_token = AsyncMock()
    async_fetch_token.return_value = {
        "access_token": "token123",
    }
    mocker.patch.object(client._oauth, "fetch_token", async_fetch_token)

    result = await client.complete_link_user("https://myapp.com/callback?code=123&state=xyz")
    assert result["app_state"] == {"foo": "bar"}
    mock_tx_store.delete.assert_awaited_once()


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

    get_refresh_token_mock = mocker.patch.object(client, "get_token_by_refresh_token", return_value={
        "access_token": "new_token",
        "expires_in": 3600
    })

    token = await client.get_access_token()
    assert token == "new_token"
    mock_state_store.set.assert_awaited_once()
    get_refresh_token_mock.assert_awaited_with({
        "refresh_token": "refresh_xyz",
        "domain": "auth0.local"
    })

@pytest.mark.asyncio
async def test_get_access_token_refresh_merging_default_scope(mocker):
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
        secret="some-secret",
        authorization_params= {
            "audience": "default",
            "scope": "openid profile email"
        }
    )

    get_refresh_token_mock = mocker.patch.object(client, "get_token_by_refresh_token", return_value={
        "access_token": "new_token",
        "expires_in": 3600
    })

    token = await client.get_access_token(scope="foo:bar")
    assert token == "new_token"
    mock_state_store.set.assert_awaited_once()
    get_refresh_token_mock.assert_awaited_with({
        "refresh_token": "refresh_xyz",
        "domain": "auth0.local",
        "audience": "default",
        "scope": "openid profile email foo:bar"
    })

@pytest.mark.asyncio
async def test_get_access_token_refresh_with_auth_params_scope(mocker):
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
        secret="some-secret",
        authorization_params= {
            "scope": "openid profile email"
        }
    )

    get_refresh_token_mock = mocker.patch.object(client, "get_token_by_refresh_token", return_value={
        "access_token": "new_token",
        "expires_in": 3600
    })

    token = await client.get_access_token()
    assert token == "new_token"
    mock_state_store.set.assert_awaited_once()
    get_refresh_token_mock.assert_awaited_with({
        "refresh_token": "refresh_xyz",
        "domain": "auth0.local",
        "scope": "openid profile email"
    })

@pytest.mark.asyncio
async def test_get_access_token_refresh_with_auth_params_audience(mocker):
    mock_state_store = AsyncMock()
    # expired token
    mock_state_store.get.return_value = {
        "refresh_token": "refresh_xyz",
        "token_sets": [
            {
                "audience": "my_audience",
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
        secret="some-secret",
        authorization_params= {
            "audience": "my_audience"
        }
    )

    get_refresh_token_mock = mocker.patch.object(client, "get_token_by_refresh_token", return_value={
        "access_token": "new_token",
        "expires_in": 3600
    })

    token = await client.get_access_token()
    assert token == "new_token"
    mock_state_store.set.assert_awaited_once()
    get_refresh_token_mock.assert_awaited_with({
        "refresh_token": "refresh_xyz",
        "domain": "auth0.local",
        "audience": "my_audience"
    })

@pytest.mark.asyncio
async def test_get_access_token_mrrt(mocker):
    mock_state_store = AsyncMock()
    # expired token
    mock_state_store.get.return_value = {
        "refresh_token": "refresh_xyz",
        "token_sets": [
            {
                "audience": "default",
                "access_token": "valid_token_for_other_audience",
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

    # Patch method that does the refresh call
    get_refresh_token_mock = mocker.patch.object(client, "get_token_by_refresh_token", return_value={
        "access_token": "new_token",
        "expires_in": 3600
    })

    token = await client.get_access_token(
        audience="some_audience",
        scope="foo:bar"
    )

    assert token == "new_token"
    mock_state_store.set.assert_awaited_once()
    args, kwargs = mock_state_store.set.call_args
    stored_state = args[1]
    assert "token_sets" in stored_state
    assert len(stored_state["token_sets"]) == 2
    get_refresh_token_mock.assert_awaited_with({
        "refresh_token": "refresh_xyz",
        "domain": "auth0.local",
        "audience": "some_audience",
        "scope": "foo:bar",
    })

@pytest.mark.asyncio
async def test_get_access_token_mrrt_with_auth_params_scope(mocker):
    mock_state_store = AsyncMock()
    # expired token
    mock_state_store.get.return_value = {
        "refresh_token": "refresh_xyz",
        "token_sets": [
            {
                "audience": "default",
                "access_token": "valid_token_for_other_audience",
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
        secret="some-secret",
        authorization_params= {
            "audience": "default",
            "scope": {
                "default": "openid profile email foo:bar",
                "some_audience": "foo:bar"
            }
        }
    )

    # Patch method that does the refresh call
    get_refresh_token_mock = mocker.patch.object(client, "get_token_by_refresh_token", return_value={
        "access_token": "new_token",
        "expires_in": 3600
    })

    token = await client.get_access_token(
        audience="some_audience"
    )

    assert token == "new_token"
    mock_state_store.set.assert_awaited_once()
    args, kwargs = mock_state_store.set.call_args
    stored_state = args[1]
    assert "token_sets" in stored_state
    assert len(stored_state["token_sets"]) == 2
    get_refresh_token_mock.assert_awaited_with({
        "refresh_token": "refresh_xyz",
        "domain": "auth0.local",
        "audience": "some_audience",
        "scope": "foo:bar",
    })

@pytest.mark.asyncio
async def test_get_access_token_from_store_with_multiple_audiences(mocker):
    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = {
        "refresh_token": None,
        "token_sets": [
            {
                "audience": "default",
                "access_token": "token_from_store",
                "expires_at": int(time.time()) + 500
            },
            {
                "audience": "some_audience",
                "access_token": "other_token_from_store",
                "scope": "foo:bar",
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

    get_refresh_token_mock = mocker.patch.object(client, "get_token_by_refresh_token")

    token = await client.get_access_token(
        audience="some_audience",
        scope="foo:bar"
    )

    assert token == "other_token_from_store"
    get_refresh_token_mock.assert_not_awaited()

@pytest.mark.asyncio
async def test_get_access_token_from_store_with_a_superset_of_requested_scopes(mocker):
    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = {
        "refresh_token": None,
        "token_sets": [
            {
                "audience": "default",
                "access_token": "token_from_store",
                "expires_at": int(time.time()) + 500
            },
            {
                "audience": "some_audience",
                "access_token": "other_token_from_store",
                "scope": "read:foo write:foo read:bar write:bar",
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

    get_refresh_token_mock = mocker.patch.object(client, "get_token_by_refresh_token")

    token = await client.get_access_token(
        audience="some_audience",
        scope="read:foo read:bar"
    )

    assert token == "other_token_from_store"
    get_refresh_token_mock.assert_not_awaited()


@pytest.mark.asyncio
async def test_get_access_token_from_store_returns_minimum_matching_scopes(mocker):
    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = {
        "refresh_token": None,
        "token_sets": [
            {
                "audience": "some_audience",
                "access_token": "maximum_scope_token",
                "scope": "read:foo write:foo read:bar write:bar admin:all",
                "expires_at": int(time.time()) + 500
            },
            {
                "audience": "some_audience",
                "access_token": "minimum_scope_token",
                "scope": "read:foo write:foo read:bar write:bar",
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

    get_refresh_token_mock = mocker.patch.object(client, "get_token_by_refresh_token")

    token = await client.get_access_token(
        audience="some_audience",
        scope="read:foo read:bar"
    )

    assert token == "minimum_scope_token"
    get_refresh_token_mock.assert_not_awaited()

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
    url = await client.logout(LogoutOptions(return_to="/after_logout"))

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

    url = await client.logout(LogoutOptions(return_to= "/bye"))

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

    # Mock JWKS fetch to prevent network call
    mocker.patch.object(
        client,
        "_get_jwks_cached",
        return_value={"keys": [{"kty": "RSA", "kid": "test-key"}]}
    )

    # Mock JWT verification
    mocker.patch("jwt.get_unverified_header", return_value={"kid": "test-key"})
    mock_signing_key = mocker.MagicMock()
    mock_signing_key.key = "mock_pem_key"
    mocker.patch("jwt.PyJWK.from_dict", return_value=mock_signing_key)
    mocker.patch("jwt.decode", return_value={
        "events": {"http://schemas.openid.net/event/backchannel-logout": {}},
        "sub": "user_sub",
        "sid": "session_id_123"
    })

    await client.handle_backchannel_logout("some_logout_token")
    mock_state_store.delete_by_logout_token.assert_awaited_once_with(
        {"sub": "user_sub", "sid": "session_id_123"},
        None
    )

# Test For AuthLib Helpers

@pytest.mark.asyncio
async def test_build_link_user_url_success(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        secret="some-secret"
    )

    # Patch _fetch_oidc_metadata to return an authorization_endpoint
    mock_fetch = mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"authorization_endpoint": "https://auth0.local/authorize"}
    )

    # Example inputs
    connection = "<connection>"
    id_token = "<id_token>"
    code_verifier = "my_code_verifier"
    state = "xyz_state"
    connection_scope = "<scope>"
    authorization_params = {"redirect_uri": "/test_redirect_uri"}

    # Act: call the function
    result_url = await client._build_link_user_url(
        connection=connection,
        id_token=id_token,
        code_verifier=code_verifier,
        state=state,
        connection_scope=connection_scope,
        authorization_params=authorization_params
    )

    # Assert the URL is correct
    parsed = urlparse(result_url)
    queries = parse_qs(parsed.query)

    assert parsed.scheme == "https"
    assert parsed.netloc == "auth0.local"
    assert parsed.path == "/authorize"

    # Check query parameters
    assert queries["client_id"] == ["<client_id>"]
    assert queries["redirect_uri"] == ["/test_redirect_uri"]  # from authorization_params
    assert queries["response_type"] == ["code"]
    assert "code_challenge" in queries
    assert queries["code_challenge_method"] == ["S256"]
    assert queries["id_token_hint"] == ["<id_token>"]
    assert queries["requested_connection"] == ["<connection>"]
    assert queries["requested_connection_scope"] == ["<scope>"]
    assert queries["scope"] == ["openid link_account"]
    assert queries["state"] == ["xyz_state"]


    # Confirm we fetched the metadata if not set
    mock_fetch.assert_awaited_once()

@pytest.mark.asyncio
async def test_build_link_user_url_fallback_authorize(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        secret="some-secret"
    )

    # Patch _fetch_oidc_metadata to NOT have an authorization_endpoint
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={}  # empty dict, triggers fallback
    )

    result_url = await client._build_link_user_url(
        connection="<connection>",
        id_token="<id_token>",
        code_verifier="my_code_verifier",
        state="xyz_state",
        connection_scope="<scope>",
        authorization_params={"redirect_uri": "/test_redirect_uri"}
    )

    parsed = urlparse(result_url)
    assert parsed.scheme == "https"
    assert parsed.netloc == "auth0.local"
    assert parsed.path == "/authorize"

    queries = parse_qs(parsed.query)
    # Confirm the same query param logic
    # Just a quick check for e.g. "client_id" or "scope"
    assert queries["client_id"] == ["<client_id>"]
    assert queries["requested_connection_scope"] == ["<scope>"]
    assert queries["scope"] == ["openid link_account"]

@pytest.mark.asyncio
async def test_build_unlink_user_url_success(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        secret="some-secret"
    )

    # Patch out metadata
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"authorization_endpoint": "https://auth0.local/authorize"}
    )

    result_url = await client._build_link_user_url(
        connection="<connection>",
        id_token="<id_token>",
        code_verifier="some_verifier",
        state="xyz_unlink",
        authorization_params={"redirect_uri": "/test_redirect_uri"}
    )

    parsed = urlparse(result_url)
    queries = parse_qs(parsed.query)

    assert parsed.path == "/authorize"
    assert queries["client_id"] == ["<client_id>"]
    assert queries["redirect_uri"] == ["/test_redirect_uri"]
    assert queries["scope"] == ["openid link_account"]
    assert queries["code_challenge_method"] == ["S256"]
    assert queries["id_token_hint"] == ["<id_token>"]
    assert queries["requested_connection"] == ["<connection>"]

@pytest.mark.asyncio
async def test_build_unlink_user_url_fallback_authorize(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        secret="some-secret"
    )

    # No 'authorization_endpoint'
    mocker.patch.object(client, "_get_oidc_metadata_cached", return_value={})

    result_url = await client._build_unlink_user_url(
        connection="<connection>",
        id_token="<id_token>",
        code_verifier="verifier123",
        state="unlink_state",
        authorization_params={"redirect_uri": "/test_redirect_uri"}
    )

    parsed = urlparse(result_url)
    assert parsed.netloc == "auth0.local"
    assert parsed.path == "/authorize"

    queries = parse_qs(parsed.query)
    assert queries["scope"] == ["openid unlink_account"]


@pytest.mark.asyncio
async def test_build_unlink_user_url_with_metadata(mocker):
    # Create a client with the relevant fields
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        secret="some-secret"
    )

    # Patch the metadata fetch to include a valid authorization endpoint
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"authorization_endpoint": "https://auth0.local/authorize"}
    )

    # Inputs to _build_unlink_user_url
    connection = "<connection>"
    id_token = "<id_token>"
    code_verifier = "verifier_123"
    state = "xyz_unlink"
    authorization_params = {"redirect_uri": "/test_redirect_uri"}

    # Call the method
    result_url = await client._build_unlink_user_url(
        connection=connection,
        id_token=id_token,
        code_verifier=code_verifier,
        state=state,
        authorization_params=authorization_params
    )

    # Parse and verify the URL
    parsed = urlparse(result_url)
    queries = parse_qs(parsed.query)

    # Check domain & path
    assert parsed.scheme == "https"
    assert parsed.netloc == "auth0.local"
    assert parsed.path == "/authorize"

    # Check the main query parameters
    assert queries["client_id"] == ["<client_id>"]
    assert queries["redirect_uri"] == ["/test_redirect_uri"]
    assert queries["scope"] == ["openid unlink_account"]
    assert queries["response_type"] == ["code"]
    assert "code_challenge" in queries
    assert queries["code_challenge_method"] == ["S256"]
    assert queries["id_token_hint"] == ["<id_token>"]
    assert queries["requested_connection"] == ["<connection>"]
    assert queries["state"] == ["xyz_unlink"]

@pytest.mark.asyncio
async def test_build_unlink_user_url_no_authorization_endpoint(mocker):
    # Same client setup
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        secret="some-secret"
    )

    # Patch _fetch_oidc_metadata to return no authorization_endpoint
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={}
    )
    result_url = await client._build_unlink_user_url(
        connection="<connection>",
        id_token="<id_token>",
        code_verifier="verifier123",
        state="unlink_state",
        authorization_params={"redirect_uri": "/test_redirect_uri"}
    )

    parsed = urlparse(result_url)
    assert parsed.netloc == "auth0.local"
    assert parsed.path == "/authorize"

    queries = parse_qs(parsed.query)
    assert queries["scope"] == ["openid unlink_account"]


@pytest.mark.asyncio
async def test_backchannel_auth_with_audience_and_binding_message(mocker):
    client = ServerClient(
            domain="auth0.local",
            client_id="<client_id>",
            client_secret="<client_secret>",
            secret="some-secret",
            authorization_params={"audience": "<audience>"}
        )

    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={
            "issuer": "https://auth0.local/",
            "backchannel_authentication_endpoint": "https://auth0.local/custom-authorize",
            "token_endpoint": "https://auth0.local/custom/token"
        }
    )

    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)

    first_response = AsyncMock()
    first_response.status_code = 200

    first_response.json = MagicMock(return_value={
        "auth_req_id": "auth_req_789",
        "interval": 0.5,
        "expires_in": 60
    })

    second_response = AsyncMock()
    second_response.status_code = 200
    second_response.json = MagicMock(return_value={
        "access_token": "accessTokenWithAudienceAndBindingMessage",
        "expires_in": 60
    })

    mock_post.side_effect = [first_response, second_response]

    options = {
        "binding_message": "<binding_message>",
        "login_hint": {"sub": "<sub>"}
    }
    result = await client.backchannel_authentication(options)

    assert result["access_token"] == "accessTokenWithAudienceAndBindingMessage"
    assert mock_post.await_count == 2

@pytest.mark.asyncio
async def test_backchannel_auth_rar(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        secret="some-secret",
        authorization_params={"audience": "<audience>"}
    )

    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={
            "issuer": "https://auth0.local/",
            "backchannel_authentication_endpoint": "https://auth0.local/custom-authorize",
            "token_endpoint": "https://auth0.local/custom/token"
        }
    )

    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)

    first_response = AsyncMock()
    first_response.status_code = 200
    first_response.json = MagicMock(return_value={
        "auth_req_id": "auth_req_with_authorization_details",
        "interval": 0.5,
        "expires_in": 60
    })

    second_response = AsyncMock()
    second_response.status_code = 200
    second_response.json = MagicMock(return_value={
        "access_token": "token_with_rar",
         "authorization_details": [{"type": "accepted"}]
    })

    mock_post.side_effect = [first_response, second_response]

    options = {
        "binding_message": "<binding_message>",
        "login_hint": {"sub": "<sub>"},
        "authorization_params": {
            "authorization_details": '[{"type":"accepted"}]'
        }
    }
    result = await client.backchannel_authentication(options)

    assert result["authorization_details"][0]["type"] == "accepted"
    assert mock_post.await_count == 2

@pytest.mark.asyncio
async def test_backchannel_auth_token_exchange_failed(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        secret="some-secret",
        authorization_params={"should_fail_token_exchange": True}
    )

    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={
            "issuer": "https://auth0.local/",
            "backchannel_authentication_endpoint": "https://auth0.local/custom-authorize",
            "token_endpoint": "https://auth0.local/custom/token"
        }
    )

    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)

    first_response = AsyncMock()
    first_response.status_code = 200
    first_response.json = MagicMock(return_value={
        "auth_req_id": "should_fail_token_exchange",
        "interval": 0.5,
        "expires_in": 60
    })

    second_response = AsyncMock()
    second_response.status_code = 400
    second_response.headers = {}
    second_response.json = MagicMock(return_value={
        "error": "<error_code>",
        "error_description": "<error_description>"
    })

    mock_post.side_effect = [first_response, second_response]

    with pytest.raises(ApiError) as exc:
        await client.backchannel_authentication({
            "login_hint": {"sub": "<sub>"},
            "binding_message": "<binding_message>"
        })

    assert "Backchannel authentication failed: <error_description>" in str(exc.value)

    assert mock_post.await_count == 2

@pytest.mark.asyncio
async def test_initiate_backchannel_authentication_success(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="client_id",
        client_secret="client_secret",
        secret="some-secret"
    )

    # Mock OIDC metadata
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={
            "issuer": "https://auth0.local/",
            "backchannel_authentication_endpoint": "https://auth0.local/backchannel"
        }
    )

    # Mock httpx.AsyncClient.post
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = MagicMock(return_value={
        "auth_req_id": "auth_req_123",
        "expires_in": 60,
        "interval": 2
    })
    mock_post.return_value = mock_response

    options = {
        "login_hint": {"sub": "user123"},
        "binding_message": "Test message"
    }
    result = await client.initiate_backchannel_authentication(options)
    assert result["auth_req_id"] == "auth_req_123"
    assert result["expires_in"] == 60
    assert result["interval"] == 2

@pytest.mark.asyncio
async def test_initiate_backchannel_authentication_missing_sub():
    client = ServerClient(
        domain="auth0.local",
        client_id="client_id",
        client_secret="client_secret",
        secret="some-secret"
    )
    with pytest.raises(MissingRequiredArgumentError):
        await client.initiate_backchannel_authentication({"login_hint": {}})

@pytest.mark.asyncio
async def test_initiate_backchannel_authentication_error_response(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="client_id",
        client_secret="client_secret",
        secret="some-secret"
    )
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={
            "issuer": "https://auth0.local/",
            "backchannel_authentication_endpoint": "https://auth0.local/backchannel"
        }
    )
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 400
    mock_response.json = MagicMock(return_value={
        "error": "invalid_request",
        "error_description": "Bad request"
    })
    mock_post.return_value = mock_response

    with pytest.raises(ApiError) as exc:
        await client.initiate_backchannel_authentication({"login_hint": {"sub": "user123"}})
    assert "Bad request" in str(exc.value)

@pytest.mark.asyncio
async def test_authorization_params_not_dict_raises():
    client = ServerClient("domain", "client_id", "client_secret", secret="s")
    with pytest.raises(ApiError) as exc:
        await client.initiate_backchannel_authentication({
            "login_hint": {"sub": "user_id"},
            "authorization_params": "not_a_dict"
        })
    assert "authorization_params must be a dict" in str(exc.value)

@pytest.mark.asyncio
async def test_requested_expiry_not_positive_int_raises():
    client = ServerClient("domain", "client_id", "client_secret", secret="s")
    with pytest.raises(ApiError) as exc:
        await client.initiate_backchannel_authentication({
            "login_hint": {"sub": "user_id"},
            "authorization_params": {"requested_expiry": -10}
        })
    assert "requested_expiry must be a positive integer" in str(exc.value)

@pytest.mark.asyncio
async def test_backchannel_authentication_grant_success(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="client_id",
        client_secret="client_secret",
        secret="some-secret"
    )
    # Mock OIDC metadata
    client._oauth.metadata = {"token_endpoint": "https://auth0.local/token"}

    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = MagicMock(return_value={
        "access_token": "token_abc",
        "expires_in": 3600
    })
    mock_post.return_value = mock_response

    result = await client.backchannel_authentication_grant("auth_req_123")
    assert result["access_token"] == "token_abc"
    assert result["expires_in"] == 3600

@pytest.mark.asyncio
async def test_backchannel_authentication_grant_missing_auth_req_id():
    client = ServerClient(
        domain="auth0.local",
        client_id="client_id",
        client_secret="client_secret",
        secret="some-secret"
    )
    with pytest.raises(MissingRequiredArgumentError):
        await client.backchannel_authentication_grant("")

@pytest.mark.asyncio
async def test_backchannel_authentication_grant_error_response(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="client_id",
        client_secret="client_secret",
        secret="some-secret"
    )
    client._oauth.metadata = {"token_endpoint": "https://auth0.local/token"}

    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 400
    mock_response.json = MagicMock(return_value={
        "error": "invalid_grant",
        "error_description": "Invalid auth_req_id",
        "interval": 2
    })
    mock_response.headers = {"Retry-After": "2"}
    mock_post.return_value = mock_response

    with pytest.raises(PollingApiError) as exc:
        await client.backchannel_authentication_grant("bad_auth_req_id")
    assert "Invalid auth_req_id" in str(exc.value)
    assert 2 == exc.value.interval
    assert "invalid_grant" in str(exc.value.code)

@pytest.mark.asyncio
async def test_backchannel_authentication_grant_json_decode_error(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="client_id",
        client_secret="client_secret",
        secret="some-secret"
    )
    client._oauth.metadata = {"token_endpoint": "https://auth0.local/token"}

    # Mock httpx.AsyncClient.post to return a response whose .json() raises JSONDecodeError
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = MagicMock(side_effect=json.JSONDecodeError("Expecting value", "not json", 0))
    mock_post.return_value = mock_response

    with pytest.raises(ApiError) as exc:
        await client.backchannel_authentication_grant("auth_req_123")

    assert exc.value.code == "invalid_response"
    assert "Failed to parse token response as JSON" in str(exc.value)

@pytest.mark.asyncio
async def test_get_token_for_connection_success(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        secret="some-secret"
    )

    mocker.patch.object(
        client._oauth,
        "metadata",
        {"token_endpoint": "https://auth0.local/token"}
    )

    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)

    success_response = AsyncMock()
    success_response.status_code = 200
    success_response.json = MagicMock(return_value={
        "access_token": "federated_access_token_value",
        "expires_in": 3600,
        "scope": "openid profile"
    })
    success_response.headers = {}
    mock_post.return_value = success_response


    result = await client.get_token_for_connection({
        "connection": "<connection>",
        "refresh_token": "<refresh_token>",
        "login_hint": "<sub>"
    })


    assert result is not None
    assert result["access_token"] == "federated_access_token_value"
    assert "expires_at" in result
    assert result["scope"] == "openid profile"

    mock_post.assert_awaited_once()
    args, kwargs = mock_post.call_args
    assert kwargs["data"]["connection"] == "<connection>"
    assert kwargs["data"]["subject_token"] == "<refresh_token>"
    assert kwargs["data"]["login_hint"] == "<sub>"

@pytest.mark.asyncio
async def test_get_token_for_connection_exchange_failed(mocker):

    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        secret="some-secret"
    )

    mocker.patch.object(
        client._oauth,
        "metadata",
        {"token_endpoint": "https://auth0.local/token"}
    )

    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)


    fail_response = AsyncMock()
    fail_response.status_code = 400
    fail_response.json = MagicMock(return_value={
        "error": "token_for_connection_error",
        "error_description": "<error_description>"
    })
    mock_post.return_value = fail_response


    with pytest.raises(AccessTokenForConnectionError) as exc:
        await client.get_token_for_connection({
            "connection": "<connection>",
            "refresh_token": "<refresh_token_should_fail>"
        })


    assert "Failed to get token for connection: 400" in str(exc.value)

    mock_post.assert_awaited_once()

@pytest.mark.asyncio
async def test_get_token_by_refresh_token_success(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        secret="some-secret"
    )

    mocker.patch.object(
        client._oauth,
        "metadata",
        {"token_endpoint": "https://auth0.local/token"}
    )

    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)

    success_response = AsyncMock()
    success_response.status_code = 200
    success_response.json = MagicMock(return_value={
        "access_token": "my_new_access_token",
        "expires_in": 3600
    })
    mock_post.return_value = success_response

    token_data = await client.get_token_by_refresh_token({"refresh_token": "abc"})


    assert token_data is not None
    assert token_data["access_token"] == "my_new_access_token"

    assert "expires_at" in token_data

    now = int(time.time())
    assert now <= token_data["expires_at"] <= now + 3700


    mock_post.assert_awaited_once()
    args, kwargs = mock_post.call_args

    assert kwargs["data"]["refresh_token"] == "abc"
    assert kwargs["data"]["grant_type"] == "refresh_token"

@pytest.mark.asyncio
async def test_get_token_by_refresh_token_exchange_failed(mocker):
    # Create the client
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        secret="some-secret"
    )

    mocker.patch.object(
        client._oauth,
        "metadata",
        {"token_endpoint": "https://auth0.local/token"}
    )

    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)

    fail_response = AsyncMock()
    fail_response.status_code = 400
    fail_response.json = MagicMock(return_value={
        "error": "<error_code>",
        "error_description": "<error_description>"
    })
    mock_post.return_value = fail_response

    with pytest.raises(ApiError) as exc:
        await client.get_token_by_refresh_token({"refresh_token": "<refresh_token_should_fail>"})


    assert "<error_description>" in str(exc.value)

    mock_post.assert_awaited_once()

    args, kwargs = mock_post.call_args
    assert kwargs["data"]["refresh_token"] == "<refresh_token_should_fail>"

@pytest.mark.asyncio
async def test_start_connect_account_calls_connect_and_builds_url(mocker):
    # Setup
    mock_transaction_store = AsyncMock()
    mock_state_store = AsyncMock()

    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        state_store=mock_state_store,
        transaction_store=mock_transaction_store,
        secret="some-secret"
    )

    mocker.patch.object(client, "get_access_token", AsyncMock(return_value="<access_token>"))
    mock_my_account_client = AsyncMock(MyAccountClient)
    mocker.patch.object(client, "_my_account_client", mock_my_account_client)
    mock_my_account_client.connect_account.return_value = ConnectAccountResponse(
        auth_session="<auth_session>",
        connect_uri="http://auth0.local/connected_accounts/connect",
        connect_params=ConnectParams(
            ticket="ticket123"
        ),
        expires_in=300
    )

    mocker.patch.object(PKCE, "generate_random_string", return_value="<state>")
    mocker.patch.object(PKCE, "generate_code_verifier", return_value="<code_verifier>")
    mocker.patch.object(PKCE, "generate_code_challenge", return_value="<code_challenge>")

    # Act
    url = await client.start_connect_account(
        options=ConnectAccountOptions(
            connection="<connection>",
            app_state="<app_state>",
            redirect_uri="/test_redirect_uri"
        )
    )

    # Assert
    assert url == "http://auth0.local/connected_accounts/connect?ticket=ticket123"
    mock_my_account_client.connect_account.assert_awaited_with(
        access_token="<access_token>",
        request=ConnectAccountRequest(
            connection="<connection>",
            redirect_uri="/test_redirect_uri",
            code_challenge_method="S256",
            code_challenge="<code_challenge>",
            state= "<state>"
        )
    )
    mock_transaction_store.set.assert_awaited_with(
        "_a0_tx:<state>",
        TransactionData(
            code_verifier="<code_verifier>",
            app_state="<app_state>",
            auth_session="<auth_session>",
            redirect_uri="/test_redirect_uri"
        ),
        options=ANY
    )

@pytest.mark.asyncio
async def test_start_connect_account_with_scopes(mocker):
    # Setup
    mock_transaction_store = AsyncMock()
    mock_state_store = AsyncMock()

    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        state_store=mock_state_store,
        transaction_store=mock_transaction_store,
        secret="some-secret"
    )

    mocker.patch.object(client, "get_access_token", AsyncMock(return_value="<access_token>"))
    mock_my_account_client = AsyncMock(MyAccountClient)
    mocker.patch.object(client, "_my_account_client", mock_my_account_client)
    mock_my_account_client.connect_account.return_value = ConnectAccountResponse(
        auth_session="<auth_session>",
        connect_uri="http://auth0.local/connected_accounts/connect",
        connect_params=ConnectParams(
            ticket="ticket123"
        ),
        expires_in=300
    )

    # Act
    await client.start_connect_account(
        options=ConnectAccountOptions(
            connection="<connection>",
            scopes=["scope1", "scope2", "scope3"],
            redirect_uri="/test_redirect_uri"
        )
    )

    # Assert
    mock_my_account_client.connect_account.assert_awaited()
    request = mock_my_account_client.connect_account.mock_calls[0].kwargs["request"]
    assert request.scopes == ["scope1", "scope2", "scope3"]

@pytest.mark.asyncio
async def test_start_connect_account_default_redirect_uri(mocker):
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
        redirect_uri="/default_redirect_uri"
    )

    mocker.patch.object(client, "get_access_token", AsyncMock(return_value="<access_token>"))
    mock_my_account_client = AsyncMock(MyAccountClient)
    mocker.patch.object(client, "_my_account_client", mock_my_account_client)
    mock_my_account_client.connect_account.return_value = ConnectAccountResponse(
        auth_session="<auth_session>",
        connect_uri="http://auth0.local/connected_accounts/connect",
        connect_params=ConnectParams(
            ticket="ticket123",
        ),
        expires_in=300
    )

    mocker.patch.object(PKCE, "generate_random_string", return_value="<state>")
    mocker.patch.object(PKCE, "generate_code_verifier", return_value="<code_verifier>")
    mocker.patch.object(PKCE, "generate_code_challenge", return_value="<code_challenge>")

    # Act
    url = await client.start_connect_account(
        options=ConnectAccountOptions(
            connection="<connection>",
            app_state="<app_state>"
        )
    )

    # Assert
    assert url == "http://auth0.local/connected_accounts/connect?ticket=ticket123"
    mock_my_account_client.connect_account.assert_awaited_with(
        access_token="<access_token>",
        request=ConnectAccountRequest(
            connection="<connection>",
            redirect_uri="/default_redirect_uri",
            code_challenge_method="S256",
            code_challenge="<code_challenge>",
            state= "<state>"
        )
    )
    mock_transaction_store.set.assert_awaited_with(
        "_a0_tx:<state>",
        TransactionData(
            code_verifier="<code_verifier>",
            app_state="<app_state>",
            auth_session="<auth_session>",
            redirect_uri="/default_redirect_uri"
        ),
        options=ANY
    )

@pytest.mark.asyncio
async def test_start_connect_account_no_redirect_uri(mocker):
    # Setup
    mock_transaction_store = AsyncMock()
    mock_state_store = AsyncMock()

    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        state_store=mock_state_store,
        transaction_store=mock_transaction_store,
        secret="some-secret"
    )

    # Act
    with pytest.raises(MissingRequiredArgumentError) as exc:
        await client.start_connect_account(
            options=ConnectAccountOptions(
                connection="<connection>"
            )
        )

    # Assert
    assert "redirect_uri" in str(exc.value)

@pytest.mark.asyncio
async def test_complete_connect_account_calls_complete(mocker):
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
        redirect_uri="/test_redirect_uri"
    )

    mocker.patch.object(client, "get_access_token", AsyncMock(return_value="<access_token>"))
    mock_my_account_client = AsyncMock(MyAccountClient)
    mocker.patch.object(client, "_my_account_client", mock_my_account_client)

    mock_transaction_store.get.return_value = TransactionData(
        code_verifier="<code_verifier>",
        app_state="<state>",
        auth_session="<auth_session>",
        redirect_uri="/test_redirect_uri"
    )

    # Act
    await client.complete_connect_account(
        url="/test_redirect_uri?connect_code=<connect_code>&state=<state>"
    )

    # Assert
    mock_my_account_client.complete_connect_account.assert_awaited_with(
        access_token="<access_token>",
        request=CompleteConnectAccountRequest(
            auth_session="<auth_session>",
            connect_code="<connect_code>",
            redirect_uri="/test_redirect_uri",
            code_verifier="<code_verifier>"
        )
    )

@pytest.mark.asyncio
async def test_complete_connect_account_no_connect_code(mocker):
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
        redirect_uri="/test_redirect_uri"
    )

    mock_my_account_client = AsyncMock(MyAccountClient)
    mocker.patch.object(client, "_my_account_client", mock_my_account_client)

    mock_transaction_store.get.return_value = None  # no transaction

    # Act
    with pytest.raises(MissingRequiredArgumentError) as exc:
        await client.complete_connect_account(
            url="/test_redirect_uri?state=<state>"
        )

    # Assert
    assert "connect_code" in str(exc.value)
    mock_my_account_client.complete_connect_account.assert_not_awaited()

@pytest.mark.asyncio
async def test_complete_connect_account_no_state(mocker):
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
        redirect_uri="/test_redirect_uri"
    )

    mock_my_account_client = AsyncMock(MyAccountClient)
    mocker.patch.object(client, "_my_account_client", mock_my_account_client)

    mock_transaction_store.get.return_value = None  # no transaction

    # Act
    with pytest.raises(MissingRequiredArgumentError) as exc:
        await client.complete_connect_account(
            url="/test_redirect_uri?connect_code=<connect_code>"
        )

    # Assert
    assert "state" in str(exc.value)
    mock_my_account_client.complete_connect_account.assert_not_awaited()

@pytest.mark.asyncio
async def test_complete_connect_account_no_transactions(mocker):
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
        redirect_uri="/test_redirect_uri"
    )

    mock_my_account_client = AsyncMock(MyAccountClient)
    mocker.patch.object(client, "_my_account_client", mock_my_account_client)

    mock_transaction_store.get.return_value = None  # no transaction

    # Act
    with pytest.raises(MissingTransactionError) as exc:
        await client.complete_connect_account(
            url="/test_redirect_uri?connect_code=<connect_code>&state=<state>"
        )

    # Assert
    assert "transaction" in str(exc.value)
    mock_my_account_client.complete_connect_account.assert_not_awaited()


# =============================================================================
# Requirement 1: Multiple Issuer Configuration Methods Tests
# =============================================================================

@pytest.mark.asyncio
async def test_domain_as_static_string():
    """Test Method 1: Static domain string configuration."""
    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="test_client_id",
        client_secret="test_client_secret",
        secret="test_secret_key_32_chars_long!!"
    )
    
    assert client._domain == "tenant.auth0.com"
    assert client._domain_resolver is None


@pytest.mark.asyncio
async def test_domain_as_callable_function():
    """Test Method 2: Domain resolver function configuration."""
    async def domain_resolver(store_options):
        return "tenant.auth0.com"
    
    client = ServerClient(
        domain=domain_resolver,
        client_id="test_client_id",
        client_secret="test_client_secret",
        secret="test_secret_key_32_chars_long!!"
    )
    
    assert client._domain is None
    assert client._domain_resolver == domain_resolver


@pytest.mark.asyncio
async def test_missing_domain_raises_configuration_error():
    """Test that missing domain parameter raises ConfigurationError."""
    with pytest.raises(ConfigurationError, match="Domain is required"):
        ServerClient(
            domain=None,
            client_id="test_client_id",
            client_secret="test_client_secret",
            secret="test_secret_key_32_chars_long!!"
        )


@pytest.mark.asyncio
async def test_invalid_domain_type_list():
    """Test that list domain raises ConfigurationError."""
    with pytest.raises(ConfigurationError, match="must be either a string or a callable"):
        ServerClient(
            domain=["tenant.auth0.com"],
            client_id="test_client_id",
            client_secret="test_client_secret",
            secret="test_secret_key_32_chars_long!!"
        )


@pytest.mark.asyncio
async def test_empty_domain_string():
    """Test that empty domain string raises ConfigurationError."""
    with pytest.raises(ConfigurationError, match="Domain cannot be empty"):
        ServerClient(
            domain="",
            client_id="test_client_id",
            client_secret="test_client_secret",
            secret="test_secret_key_32_chars_long!!"
        )


# =============================================================================
# Requirement 2: Domain Resolver Context Tests
# =============================================================================

@pytest.mark.asyncio
async def test_domain_resolver_receives_context(mocker):
    """Test that domain resolver receives DomainResolverContext with request data."""
    received_context = None
    
    async def domain_resolver(context):
        nonlocal received_context
        received_context = context
        return "tenant.auth0.com"
    
    client = ServerClient(
        domain=domain_resolver,
        client_id="test_client",
        client_secret="test_secret",
        secret="test_secret_key_32_chars_long!!",
        transaction_store=AsyncMock(),
        state_store=AsyncMock()
    )
    
    # Mock request with headers
    mock_request = MagicMock()
    mock_request.url = "https://a.my-app.com/auth/login"
    mock_request.headers = {"host": "a.my-app.com", "x-forwarded-host": "a.my-app.com"}
    
    # Mock OIDC metadata fetch
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"issuer": "https://tenant.auth0.com/", "authorization_endpoint": "https://tenant.auth0.com/authorize"}
    )
    
    try:
        await client.start_interactive_login(store_options={"request": mock_request})
    except:
        pass  # We only care about context being passed
    
    assert received_context is not None
    assert isinstance(received_context, DomainResolverContext)
    assert received_context.request_url == "https://a.my-app.com/auth/login"
    assert received_context.request_headers.get("host") == "a.my-app.com"


@pytest.mark.asyncio
async def test_domain_resolver_error_on_none():
    """Test that domain resolver returning None raises DomainResolverError."""
    async def bad_resolver(context):
        return None
    
    client = ServerClient(
        domain=bad_resolver,
        client_id="test_client",
        client_secret="test_secret",
        secret="test_secret_key_32_chars_long!!",
        transaction_store=AsyncMock(),
        state_store=AsyncMock()
    )
    
    with pytest.raises(DomainResolverError, match="returned None"):
        await client.start_interactive_login(store_options={"request": MagicMock()})


@pytest.mark.asyncio
async def test_domain_resolver_error_on_empty_string():
    """Test that domain resolver returning empty string raises DomainResolverError."""
    async def bad_resolver(context):
        return ""
    
    client = ServerClient(
        domain=bad_resolver,
        client_id="test_client",
        client_secret="test_secret",
        secret="test_secret_key_32_chars_long!!",
        transaction_store=AsyncMock(),
        state_store=AsyncMock()
    )
    
    with pytest.raises(DomainResolverError, match="empty string"):
        await client.start_interactive_login(store_options={"request": MagicMock()})


@pytest.mark.asyncio
async def test_domain_resolver_error_on_exception():
    """Test that domain resolver exceptions are wrapped in DomainResolverError."""
    async def bad_resolver(context):
        raise ValueError("Something went wrong")
    
    client = ServerClient(
        domain=bad_resolver,
        client_id="test_client",
        client_secret="test_secret",
        secret="test_secret_key_32_chars_long!!",
        transaction_store=AsyncMock(),
        state_store=AsyncMock()
    )
    
    with pytest.raises(DomainResolverError, match="raised an exception"):
        await client.start_interactive_login(store_options={"request": MagicMock()})


@pytest.mark.asyncio
async def test_domain_resolver_with_no_request(mocker):
    """Test that domain resolver works with empty context when no request."""
    received_context = None
    
    async def domain_resolver(context):
        nonlocal received_context
        received_context = context
        return "tenant.auth0.com"
    
    client = ServerClient(
        domain=domain_resolver,
        client_id="test_client",
        client_secret="test_secret",
        secret="test_secret_key_32_chars_long!!",
        transaction_store=AsyncMock(),
        state_store=AsyncMock()
    )
    
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"issuer": "https://tenant.auth0.com/", "authorization_endpoint": "https://tenant.auth0.com/authorize"}
    )
    
    try:
        await client.start_interactive_login(store_options=None)
    except:
        pass
    
    assert received_context is not None
    assert received_context.request_url is None
    assert received_context.request_headers is None


@pytest.mark.asyncio
async def test_domain_resolver_error_on_non_string_type():
    """Test that domain resolver returning non-string raises DomainResolverError."""
    async def bad_resolver(context):
        return 12345
    
    client = ServerClient(
        domain=bad_resolver,
        client_id="test_client",
        client_secret="test_secret",
        secret="test_secret_key_32_chars_long!!",
        transaction_store=AsyncMock(),
        state_store=AsyncMock()
    )
    
    with pytest.raises(DomainResolverError, match="must return a string"):
        await client.start_interactive_login(store_options={"request": MagicMock()})


# =============================================================================
# Requirement 3: OIDC Metadata and JWKS Fetching Tests
# =============================================================================


@pytest.mark.asyncio
async def test_fetch_jwks_success():
    """Test successful JWKS fetch from URI."""
    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="test_client",
        client_secret="test_secret",
        secret="test_secret_key_32_chars_long!!",
        transaction_store=AsyncMock(),
        state_store=AsyncMock()
    )
    
    mock_jwks = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": "test-key-id",
                "n": "test-modulus",
                "e": "AQAB"
            }
        ]
    }
    
    # Mock httpx client
    mock_response = MagicMock()
    mock_response.json.return_value = mock_jwks
    mock_response.raise_for_status = MagicMock()
    
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None
    mock_client.get.return_value = mock_response
    
    with patch('httpx.AsyncClient', return_value=mock_client):
        jwks = await client._fetch_jwks("https://tenant.auth0.com/.well-known/jwks.json")
    
    assert jwks == mock_jwks
    assert "keys" in jwks
    mock_client.get.assert_awaited_once_with("https://tenant.auth0.com/.well-known/jwks.json")


@pytest.mark.asyncio
async def test_fetch_jwks_failure():
    """Test JWKS fetch failure raises ApiError."""
    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="test_client",
        client_secret="test_secret",
        secret="test_secret_key_32_chars_long!!",
        transaction_store=AsyncMock(),
        state_store=AsyncMock()
    )
    
    # Mock httpx client to raise exception
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None
    mock_client.get.side_effect = Exception("Network error")
    
    with patch('httpx.AsyncClient', return_value=mock_client):
        with pytest.raises(ApiError, match="Failed to fetch JWKS"):
            await client._fetch_jwks("https://tenant.auth0.com/.well-known/jwks.json")


@pytest.mark.asyncio
async def test_oidc_metadata_caching():
    """Test OIDC metadata is cached and reused."""
    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="test_client",
        client_secret="test_secret",
        secret="test_secret_key_32_chars_long!!",
        transaction_store=AsyncMock(),
        state_store=AsyncMock()
    )
    
    mock_metadata = {
        "issuer": "https://tenant.auth0.com/",
        "authorization_endpoint": "https://tenant.auth0.com/authorize",
        "token_endpoint": "https://tenant.auth0.com/oauth/token",
        "jwks_uri": "https://tenant.auth0.com/.well-known/jwks.json"
    }
    
    # Mock _fetch_oidc_metadata to track calls
    fetch_count = 0
    async def mock_fetch(domain):
        nonlocal fetch_count
        fetch_count += 1
        return mock_metadata
    
    client._fetch_oidc_metadata = mock_fetch
    
    # First call - should fetch
    result1 = await client._get_oidc_metadata_cached("tenant.auth0.com")
    assert result1 == mock_metadata
    assert fetch_count == 1
    
    # Second call - should use cache
    result2 = await client._get_oidc_metadata_cached("tenant.auth0.com")
    assert result2 == mock_metadata
    assert fetch_count == 1  # Should NOT increment
    
    # Verify cache contains data
    assert "tenant.auth0.com" in client._metadata_cache
    assert client._metadata_cache["tenant.auth0.com"]["data"] == mock_metadata


@pytest.mark.asyncio
async def test_oidc_metadata_cache_expiration():
    """Test OIDC metadata cache expires after TTL."""
    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="test_client",
        client_secret="test_secret",
        secret="test_secret_key_32_chars_long!!",
        transaction_store=AsyncMock(),
        state_store=AsyncMock()
    )
    
    # Set short TTL for testing
    client._cache_ttl = 1  # 1 second
    
    mock_metadata = {
        "issuer": "https://tenant.auth0.com/",
        "jwks_uri": "https://tenant.auth0.com/.well-known/jwks.json"
    }
    
    fetch_count = 0
    async def mock_fetch(domain):
        nonlocal fetch_count
        fetch_count += 1
        return mock_metadata
    
    client._fetch_oidc_metadata = mock_fetch
    
    # First call
    await client._get_oidc_metadata_cached("tenant.auth0.com")
    assert fetch_count == 1
    
    # Wait for cache to expire
    time.sleep(1.1)
    
    # Second call after expiration - should fetch again
    await client._get_oidc_metadata_cached("tenant.auth0.com")
    assert fetch_count == 2


@pytest.mark.asyncio
async def test_jwks_caching():
    """Test JWKS is cached and reused."""
    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="test_client",
        client_secret="test_secret",
        secret="test_secret_key_32_chars_long!!",
        transaction_store=AsyncMock(),
        state_store=AsyncMock()
    )
    
    mock_metadata = {
        "issuer": "https://tenant.auth0.com/",
        "jwks_uri": "https://tenant.auth0.com/.well-known/jwks.json"
    }
    
    mock_jwks = {
        "keys": [{"kty": "RSA", "kid": "key1"}]
    }
    
    # Mock the fetch methods
    client._get_oidc_metadata_cached = AsyncMock(return_value=mock_metadata)
    
    fetch_count = 0
    async def mock_fetch_jwks(uri):
        nonlocal fetch_count
        fetch_count += 1
        return mock_jwks
    
    client._fetch_jwks = mock_fetch_jwks
    
    # First call - should fetch
    result1 = await client._get_jwks_cached("tenant.auth0.com", mock_metadata)
    assert result1 == mock_jwks
    assert fetch_count == 1
    
    # Second call - should use cache
    result2 = await client._get_jwks_cached("tenant.auth0.com", mock_metadata)
    assert result2 == mock_jwks
    assert fetch_count == 1  # Should NOT increment


@pytest.mark.asyncio
async def test_jwks_cache_size_limit():
    """Test JWKS cache enforces max size limit with FIFO eviction."""
    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="test_client",
        client_secret="test_secret",
        secret="test_secret_key_32_chars_long!!",
        transaction_store=AsyncMock(),
        state_store=AsyncMock()
    )
    
    # Set small cache size for testing
    client._cache_max_size = 3
    
    mock_jwks = {"keys": [{"kty": "RSA"}]}
    
    # Mock methods
    async def mock_fetch_metadata(domain):
        return {"jwks_uri": f"https://{domain}/.well-known/jwks.json"}
    
    async def mock_fetch_jwks(uri):
        return mock_jwks
    
    client._fetch_oidc_metadata = mock_fetch_metadata
    client._fetch_jwks = mock_fetch_jwks
    
    # Fill cache to limit
    await client._get_jwks_cached("domain1.auth0.com")
    await client._get_jwks_cached("domain2.auth0.com")
    await client._get_jwks_cached("domain3.auth0.com")
    
    assert len(client._jwks_cache) == 3
    assert "domain1.auth0.com" in client._jwks_cache
    
    # Add one more - should evict oldest (domain1)
    await client._get_jwks_cached("domain4.auth0.com")
    
    assert len(client._jwks_cache) == 3
    assert "domain1.auth0.com" not in client._jwks_cache  # Evicted
    assert "domain4.auth0.com" in client._jwks_cache


@pytest.mark.asyncio
async def test_jwks_missing_uri_raises_error():
    """Test that missing jwks_uri in metadata raises ApiError."""
    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="test_client",
        client_secret="test_secret",
        secret="test_secret_key_32_chars_long!!",
        transaction_store=AsyncMock(),
        state_store=AsyncMock()
    )
    
    # Metadata WITHOUT jwks_uri
    mock_metadata_no_jwks_uri = {
        "issuer": "https://tenant.auth0.com/",
        "authorization_endpoint": "https://tenant.auth0.com/authorize"
        # No jwks_uri
    }
    
    client._get_oidc_metadata_cached = AsyncMock(return_value=mock_metadata_no_jwks_uri)
    
    # Should raise ApiError when jwks_uri is missing
    with pytest.raises(ApiError) as exc_info:
        await client._get_jwks_cached("tenant.auth0.com")
    
    assert exc_info.value.code == "missing_jwks_uri"
    assert "non-RFC-compliant" in str(exc_info.value)


@pytest.mark.asyncio
async def test_metadata_cache_size_limit():
    """Test OIDC metadata cache enforces max size limit."""
    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="test_client",
        client_secret="test_secret",
        secret="test_secret_key_32_chars_long!!",
        transaction_store=AsyncMock(),
        state_store=AsyncMock()
    )
    
    client._cache_max_size = 2
    
    async def mock_fetch(domain):
        return {"issuer": f"https://{domain}/"}
    
    client._fetch_oidc_metadata = mock_fetch
    
    # Fill cache
    await client._get_oidc_metadata_cached("domain1.auth0.com")
    await client._get_oidc_metadata_cached("domain2.auth0.com")
    
    assert len(client._metadata_cache) == 2
    
    # Add third - should evict first
    await client._get_oidc_metadata_cached("domain3.auth0.com")
    
    assert len(client._metadata_cache) == 2
    assert "domain1.auth0.com" not in client._metadata_cache
    assert "domain3.auth0.com" in client._metadata_cache


# =============================================================================
# Requirement 4: Issuer Validation Tests
# =============================================================================


@pytest.mark.asyncio
async def test_complete_login_issuer_validation_success(mocker):
    """Test complete login with valid issuer in ID token."""
    mock_tx_store = AsyncMock()
    mock_tx_store.get.return_value = TransactionData(
        code_verifier="123",
        origin_domain="tenant.auth0.com",
        origin_issuer="https://tenant.auth0.com/"
    )

    mock_state_store = AsyncMock()

    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="test_client",
        client_secret="test_secret",
        transaction_store=mock_tx_store,
        state_store=mock_state_store,
        secret="test_secret_key_32_chars_long!!",
    )

    # Mock OIDC metadata
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"issuer": "https://tenant.auth0.com/", "token_endpoint": "https://tenant.auth0.com/token"}
    )

    # Mock JWKS fetch
    mocker.patch.object(
        client,
        "_get_jwks_cached",
        return_value={"keys": [{"kty": "RSA", "kid": "test-key"}]}
    )

    # Mock OAuth fetch_token
    async_fetch_token = AsyncMock()
    async_fetch_token.return_value = {
        "access_token": "token123",
        "id_token": "id_token_jwt",
        "scope": "openid profile"
    }
    mocker.patch.object(client._oauth, "fetch_token", async_fetch_token)

    # Mock jwt.get_unverified_header
    mocker.patch("jwt.get_unverified_header", return_value={"kid": "test-key"})
    
    # Mock PyJWK.from_dict
    mock_signing_key = mocker.MagicMock()
    mock_signing_key.key = "mock_pem_key"
    mocker.patch("jwt.PyJWK.from_dict", return_value=mock_signing_key)
    
    # Mock jwt.decode with valid issuer
    mocker.patch("jwt.decode", return_value={
        "sub": "user123",
        "iss": "https://tenant.auth0.com/",  # Matches origin_issuer
        "aud": "test_client"
    })

    # Should succeed without raising error
    result = await client.complete_interactive_login("http://localhost/callback?code=abc&state=xyz")
    
    assert result is not None
    assert "state_data" in result


@pytest.mark.asyncio
async def test_complete_login_issuer_mismatch_raises_error(mocker):
    """Test that issuer mismatch in ID token raises ApiError."""
    mock_tx_store = AsyncMock()
    mock_tx_store.get.return_value = TransactionData(
        code_verifier="123",
        origin_domain="tenant.auth0.com",
        origin_issuer="https://tenant.auth0.com/"
    )

    mock_state_store = AsyncMock()

    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="test_client",
        client_secret="test_secret",
        transaction_store=mock_tx_store,
        state_store=mock_state_store,
        secret="test_secret_key_32_chars_long!!",
    )

    # Mock OIDC metadata
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"issuer": "https://tenant.auth0.com/", "token_endpoint": "https://tenant.auth0.com/token"}
    )

    # Mock JWKS fetch
    mocker.patch.object(
        client,
        "_get_jwks_cached",
        return_value={"keys": [{"kty": "RSA", "kid": "test-key"}]}
    )

    # Mock OAuth fetch_token
    async_fetch_token = AsyncMock()
    async_fetch_token.return_value = {
        "access_token": "token123",
        "id_token": "id_token_jwt",
        "scope": "openid profile"
    }
    mocker.patch.object(client._oauth, "fetch_token", async_fetch_token)

    # Mock jwt.get_unverified_header
    mocker.patch("jwt.get_unverified_header", return_value={"kid": "test-key"})
    
    # Mock PyJWK.from_dict
    mock_signing_key = mocker.MagicMock()
    mock_signing_key.key = "mock_pem_key"
    mocker.patch("jwt.PyJWK.from_dict", return_value=mock_signing_key)
    
    # Mock jwt.decode to raise InvalidIssuerError
    mocker.patch("jwt.decode", side_effect=jwt.InvalidIssuerError("Invalid issuer"))

    # Should raise ApiError with invalid_issuer code
    with pytest.raises(ApiError) as exc_info:
        await client.complete_interactive_login("http://localhost/callback?code=abc&state=xyz")
    
    assert exc_info.value.code == "invalid_issuer"
    assert "issuer mismatch" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_normalize_domain_handles_different_schemes():
    """Test that _normalize_domain handles various URL schemes correctly."""
    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="test_client",
        client_secret="test_secret",
        secret="test_secret_key_32_chars_long!!",
        transaction_store=AsyncMock(),
        state_store=AsyncMock()
    )

    # Test domain without scheme
    assert client._normalize_domain("auth0.com") == "https://auth0.com"
    
    # Test domain with https scheme (should remain unchanged)
    assert client._normalize_domain("https://auth0.com") == "https://auth0.com"
    
    # Test domain with http scheme (should convert to https)
    assert client._normalize_domain("http://auth0.com") == "https://auth0.com"
    
    # Test domain with trailing slash
    assert client._normalize_domain("https://auth0.com/") == "https://auth0.com/"


# =============================================================================
# Requirements 5-8: Domain-specific Session Management Tests
# =============================================================================


@pytest.mark.asyncio
async def test_session_stores_origin_domain(mocker):
    """Test that session stores origin domain from login (Requirement 5)."""
    mock_tx_store = AsyncMock()
    mock_tx_store.get.return_value = TransactionData(
        code_verifier="123",
        origin_domain="tenant1.auth0.com",
        origin_issuer="https://tenant1.auth0.com/"
    )

    captured_state = None
    async def capture_state(identifier, state_data, options=None):
        nonlocal captured_state
        captured_state = state_data
    
    mock_state_store = AsyncMock()
    mock_state_store.set = AsyncMock(side_effect=capture_state)

    client = ServerClient(
        domain="tenant1.auth0.com",
        client_id="test_client",
        client_secret="test_secret",
        transaction_store=mock_tx_store,
        state_store=mock_state_store,
        secret="test_secret_key_32_chars_long!!",
    )

    mocker.patch.object(client, "_get_oidc_metadata_cached", return_value={
        "issuer": "https://tenant1.auth0.com/",
        "token_endpoint": "https://tenant1.auth0.com/token"
    })
    mocker.patch.object(client, "_get_jwks_cached", return_value={"keys": [{"kty": "RSA", "kid": "test-key"}]})
    
    async_fetch_token = AsyncMock(return_value={
        "access_token": "token123",
        "id_token": "id_token_jwt",
        "scope": "openid"
    })
    mocker.patch.object(client._oauth, "fetch_token", async_fetch_token)
    
    # Mock JWT verification
    mocker.patch("jwt.get_unverified_header", return_value={"kid": "test-key"})
    mock_signing_key = mocker.MagicMock()
    mock_signing_key.key = "mock_pem_key"
    mocker.patch("jwt.PyJWK.from_dict", return_value=mock_signing_key)
    mocker.patch("jwt.decode", return_value={"sub": "user123", "iss": "https://tenant1.auth0.com/"})

    await client.complete_interactive_login("http://localhost/callback?code=abc&state=xyz")
    
    # Verify session has domain field set
    assert captured_state.domain == "tenant1.auth0.com"


@pytest.mark.asyncio
async def test_cross_domain_session_rejected():
    """Test that session from domain1 cannot be used with domain2 (Requirement 5)."""
    # Create session with domain1
    session_data = StateData(
        user={"sub": "user123"},
        domain="tenant1.auth0.com",
        token_sets=[],
        internal={"sid": "123", "created_at": int(time.time())}
    )
    
    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = session_data
    
    # Domain resolver returns domain2 (different from session)
    async def domain_resolver(context):
        return "tenant2.auth0.com"
    
    client = ServerClient(
        domain=domain_resolver,
        client_id="test_client",
        client_secret="test_secret",
        transaction_store=AsyncMock(),
        state_store=mock_state_store,
        secret="test_secret_key_32_chars_long!!",
    )

    # get_user should return None (session rejected)
    user = await client.get_user(store_options={"request": {}})
    assert user is None


@pytest.mark.asyncio
async def test_logout_uses_current_domain(mocker):
    """Test that logout uses current resolved domain (Requirement 7)."""
    current_domain = "tenant2.auth0.com"
    
    async def domain_resolver(context):
        return current_domain
    
    mock_state_store = AsyncMock()
    
    client = ServerClient(
        domain=domain_resolver,
        client_id="test_client",
        client_secret="test_secret",
        transaction_store=AsyncMock(),
        state_store=mock_state_store,
        secret="test_secret_key_32_chars_long!!",
    )

    logout_url = await client.logout(store_options={"request": {}})
    
    # Verify logout URL uses current domain
    assert current_domain in logout_url
    assert logout_url.startswith(f"https://{current_domain}")


@pytest.mark.asyncio
async def test_logout_clears_session_for_current_domain():
    """Test that logout clears session (Requirement 7)."""
    mock_state_store = AsyncMock()
    
    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="test_client",
        client_secret="test_secret",
        transaction_store=AsyncMock(),
        state_store=mock_state_store,
        secret="test_secret_key_32_chars_long!!",
    )

    await client.logout()
    
    # Verify session was deleted
    mock_state_store.delete.assert_called_once()


@pytest.mark.asyncio
async def test_domain_migration_old_sessions_remain_valid():
    """Test that old sessions remain valid with old domain requests (Requirement 8)."""
    old_domain = "old-tenant.auth0.com"
    
    # Session from old domain
    session_data = StateData(
        user={"sub": "user123"},
        domain=old_domain,
        token_sets=[],
        internal={"sid": "123", "created_at": int(time.time())}
    )
    
    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = session_data
    
    # Domain resolver returns old domain
    async def domain_resolver(context):
        return old_domain
    
    client = ServerClient(
        domain=domain_resolver,
        client_id="test_client",
        client_secret="test_secret",
        transaction_store=AsyncMock(),
        state_store=mock_state_store,
        secret="test_secret_key_32_chars_long!!",
    )

    # Should successfully retrieve user
    user = await client.get_user(store_options={"request": {}})
    assert user is not None
    assert user["sub"] == "user123"


@pytest.mark.asyncio
async def test_domain_migration_new_sessions_use_new_domain(mocker):
    """Test that new logins create sessions with new domain (Requirement 8)."""
    new_domain = "new-tenant.auth0.com"
    
    mock_tx_store = AsyncMock()
    mock_tx_store.get.return_value = TransactionData(
        code_verifier="123",
        origin_domain=new_domain,
        origin_issuer=f"https://{new_domain}/"
    )

    captured_state = None
    async def capture_state(identifier, state_data, options=None):
        nonlocal captured_state
        captured_state = state_data
    
    mock_state_store = AsyncMock()
    mock_state_store.set = AsyncMock(side_effect=capture_state)

    client = ServerClient(
        domain=new_domain,
        client_id="test_client",
        client_secret="test_secret",
        transaction_store=mock_tx_store,
        state_store=mock_state_store,
        secret="test_secret_key_32_chars_long!!",
    )

    mocker.patch.object(client, "_get_oidc_metadata_cached", return_value={
        "issuer": f"https://{new_domain}/",
        "token_endpoint": f"https://{new_domain}/token"
    })
    mocker.patch.object(client, "_get_jwks_cached", return_value={"keys": [{"kty": "RSA", "kid": "test-key"}]})
    
    async_fetch_token = AsyncMock(return_value={
        "access_token": "token123",
        "id_token": "id_token_jwt",
        "scope": "openid"
    })
    mocker.patch.object(client._oauth, "fetch_token", async_fetch_token)
    
    # Mock JWT verification
    mocker.patch("jwt.get_unverified_header", return_value={"kid": "test-key"})
    mock_signing_key = mocker.MagicMock()
    mock_signing_key.key = "mock_pem_key"
    mocker.patch("jwt.PyJWK.from_dict", return_value=mock_signing_key)
    mocker.patch("jwt.decode", return_value={"sub": "user123", "iss": f"https://{new_domain}/"})

    await client.complete_interactive_login("http://localhost/callback?code=abc&state=xyz")
    
    # Verify new session has new domain
    assert captured_state.domain == new_domain


@pytest.mark.asyncio
async def test_domain_migration_sessions_isolated():
    """Test that old domain sessions cannot be used with new domain (Requirement 8)."""
    old_domain = "old-tenant.auth0.com"
    new_domain = "new-tenant.auth0.com"
    
    # Session from old domain
    session_data = StateData(
        user={"sub": "user123"},
        domain=old_domain,
        token_sets=[],
        internal={"sid": "123", "created_at": int(time.time())}
    )
    
    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = session_data
    
    # Domain resolver returns NEW domain (migration happened)
    async def domain_resolver(context):
        return new_domain
    
    client = ServerClient(
        domain=domain_resolver,
        client_id="test_client",
        client_secret="test_secret",
        transaction_store=AsyncMock(),
        state_store=mock_state_store,
        secret="test_secret_key_32_chars_long!!",
    )

    # Should reject old session
    user = await client.get_user(store_options={"request": {}})
    assert user is None