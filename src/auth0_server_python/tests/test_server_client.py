import base64
import json
import time
import unicodedata
from unittest.mock import ANY, AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from jwcrypto import jwk

from auth0_server_python.auth_schemes.dpop_auth import DPoPAuth
from auth0_server_python.auth_server.mfa_client import MfaClient
from auth0_server_python.auth_server.my_account_client import MyAccountClient
from auth0_server_python.auth_server.server_client import ServerClient
from auth0_server_python.auth_types import (
    CompleteConnectAccountRequest,
    ConnectAccountOptions,
    ConnectAccountRequest,
    ConnectAccountResponse,
    ConnectedAccount,
    ConnectedAccountConnection,
    ConnectParams,
    CustomTokenExchangeOptions,
    DomainResolverContext,
    ListConnectedAccountConnectionsResponse,
    ListConnectedAccountsResponse,
    LoginWithCustomTokenExchangeOptions,
    LogoutOptions,
    MfaRequirements,
    PasskeyAuthResponse,
    PasskeyLoginChallengeResponse,
    PasskeyLoginResult,
    PasskeySignupChallengeResponse,
    PasskeyTokenResponse,
    PasskeyUserProfile,
    StartInteractiveLoginOptions,
    StateData,
    TransactionData,
    UserClaims,
)
from auth0_server_python.error import (
    AccessTokenError,
    AccessTokenErrorCode,
    AccessTokenForConnectionError,
    AccessTokenForConnectionErrorCode,
    ApiError,
    BackchannelLogoutError,
    ConfigurationError,
    CustomTokenExchangeError,
    CustomTokenExchangeErrorCode,
    DomainResolverError,
    InvalidArgumentError,
    IssuerValidationError,
    MfaRequiredError,
    MissingRequiredArgumentError,
    MissingTransactionError,
    OrganizationTokenValidationError,
    PasskeyError,
    PollingApiError,
    SessionExpiredError,
    StartLinkUserError,
)
from auth0_server_python.utils import PKCE, State


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
    # The stored transaction includes an appState with domain
    mock_tx_store.get.return_value = TransactionData(
        code_verifier="123",
        app_state={"foo": "bar"},
        domain="auth0.local",
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
async def test_start_link_user_stores_domain_in_mcd(mocker):
    """Test that start_link_user stores domain in transaction in MCD mode."""
    async def domain_resolver(context):
        return "tenant1.auth0.com"

    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = {
        "id_token": "existing_id_token",
        "user": {"sub": "user123"},
        "domain": "tenant1.auth0.com"
    }

    captured_transaction = None
    async def capture_tx(identifier, transaction_data, options=None):
        nonlocal captured_transaction
        captured_transaction = transaction_data

    mock_tx_store = AsyncMock()
    mock_tx_store.set = AsyncMock(side_effect=capture_tx)

    client = ServerClient(
        domain=domain_resolver,
        client_id="test_client",
        client_secret="test_secret",
        transaction_store=mock_tx_store,
        state_store=mock_state_store,
        secret="test_secret_key_32_chars_long!!",
    )

    mocker.patch.object(client, "_get_oidc_metadata_cached", return_value={
        "issuer": "https://tenant1.auth0.com/",
        "authorization_endpoint": "https://tenant1.auth0.com/authorize",
        "token_endpoint": "https://tenant1.auth0.com/oauth/token"
    })
    mocker.patch.object(client, "_build_link_user_url", return_value="https://tenant1.auth0.com/authorize?...")

    await client.start_link_user(
        options={"connection": "google-oauth2"},
        store_options={"request": {}}
    )

    assert captured_transaction is not None
    assert captured_transaction.domain == "tenant1.auth0.com"


@pytest.mark.asyncio
async def test_start_unlink_user_stores_domain_in_mcd(mocker):
    """Test that start_unlink_user stores domain in transaction in MCD mode."""
    async def domain_resolver(context):
        return "tenant1.auth0.com"

    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = {
        "id_token": "existing_id_token",
        "user": {"sub": "user123"},
        "domain": "tenant1.auth0.com"
    }

    captured_transaction = None
    async def capture_tx(identifier, transaction_data, options=None):
        nonlocal captured_transaction
        captured_transaction = transaction_data

    mock_tx_store = AsyncMock()
    mock_tx_store.set = AsyncMock(side_effect=capture_tx)

    client = ServerClient(
        domain=domain_resolver,
        client_id="test_client",
        client_secret="test_secret",
        transaction_store=mock_tx_store,
        state_store=mock_state_store,
        secret="test_secret_key_32_chars_long!!",
    )

    mocker.patch.object(client, "_get_oidc_metadata_cached", return_value={
        "issuer": "https://tenant1.auth0.com/",
        "authorization_endpoint": "https://tenant1.auth0.com/authorize",
        "token_endpoint": "https://tenant1.auth0.com/oauth/token"
    })
    mocker.patch.object(client, "_build_unlink_user_url", return_value="https://tenant1.auth0.com/authorize?...")

    await client.start_unlink_user(
        options={"connection": "google-oauth2"},
        store_options={"request": {}}
    )

    assert captured_transaction is not None
    assert captured_transaction.domain == "tenant1.auth0.com"


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
async def test_get_session_domain_mismatch_returns_none():
    """Test that get_session returns None on domain mismatch in MCD mode."""
    session_data = StateData(
        user={"sub": "user123"},
        domain="tenant1.auth0.com",
        token_sets=[],
        internal={"sid": "123", "created_at": int(time.time())}
    )

    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = session_data

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

    session = await client.get_session(store_options={"request": {}})
    assert session is None


@pytest.mark.asyncio
async def test_get_session_domain_mismatch_with_dict_state():
    """Test domain mismatch works when state store returns plain dict (stateless cookie store)."""
    session_data = {
        "user": {"sub": "user123"},
        "domain": "tenant1.auth0.com",
        "token_sets": [],
        "internal": {"sid": "123", "created_at": int(time.time())}
    }

    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = session_data

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

    session = await client.get_session(store_options={"request": {}})
    assert session is None


@pytest.mark.asyncio
async def test_get_user_domain_mismatch_with_dict_state():
    """Test domain mismatch works when state store returns plain dict (stateless cookie store)."""
    session_data = {
        "user": {"sub": "user123", "name": "Test User"},
        "domain": "tenant1.auth0.com",
        "token_sets": [],
        "internal": {"sid": "123", "created_at": int(time.time())}
    }

    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = session_data

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

    user = await client.get_user(store_options={"request": {}})
    assert user is None


@pytest.mark.asyncio
async def test_get_user_legacy_session_rejected_in_resolver_mode():
    """Test that sessions without domain field are rejected in resolver mode."""
    session_data = {
        "user": {"sub": "user123", "name": "Test User"},
        # No "domain" field — legacy session created before MCD was enabled
    }

    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = session_data

    async def domain_resolver(context):
        return "tenant1.auth0.com"

    client = ServerClient(
        domain=domain_resolver,
        client_id="test_client",
        client_secret="test_secret",
        transaction_store=AsyncMock(),
        state_store=mock_state_store,
        secret="test_secret_key_32_chars_long!!",
    )

    user = await client.get_user(store_options={"request": {}})
    assert user is None


@pytest.mark.asyncio
async def test_get_session_legacy_session_rejected_in_resolver_mode():
    """Test that sessions without domain field are rejected in resolver mode."""
    session_data = {
        "user": {"sub": "user123"},
        "token_sets": [],
        "internal": {"sid": "123", "created_at": int(time.time())}
        # No "domain" field — legacy session
    }

    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = session_data

    async def domain_resolver(context):
        return "tenant1.auth0.com"

    client = ServerClient(
        domain=domain_resolver,
        client_id="test_client",
        client_secret="test_secret",
        transaction_store=AsyncMock(),
        state_store=mock_state_store,
        secret="test_secret_key_32_chars_long!!",
    )

    session = await client.get_session(store_options={"request": {}})
    assert session is None


@pytest.mark.asyncio
async def test_get_user_domain_normalization():
    """Test that domain comparison is case-insensitive and normalizes schemes."""
    session_data = {
        "user": {"sub": "user123", "name": "Test User"},
        "domain": "Tenant1.Auth0.Com"  # Mixed case
    }

    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = session_data

    async def domain_resolver(context):
        return "tenant1.auth0.com"  # Lowercase

    client = ServerClient(
        domain=domain_resolver,
        client_id="test_client",
        client_secret="test_secret",
        transaction_store=AsyncMock(),
        state_store=mock_state_store,
        secret="test_secret_key_32_chars_long!!",
    )

    user = await client.get_user(store_options={"request": {}})
    assert user is not None
    assert user["sub"] == "user123"


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
async def test_get_access_token_domain_mismatch_raises_error():
    """Test that get_access_token raises AccessTokenError on domain mismatch."""
    session_data = StateData(
        user={"sub": "user123"},
        domain="tenant1.auth0.com",
        token_sets=[{
            "audience": "default",
            "access_token": "token123",
            "expires_at": int(time.time()) + 500
        }],
        internal={"sid": "123", "created_at": int(time.time())}
    )

    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = session_data

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

    with pytest.raises(AccessTokenError) as exc:
        await client.get_access_token(store_options={"request": {}})
    assert exc.value.code == AccessTokenErrorCode.DOMAIN_MISMATCH


@pytest.mark.asyncio
async def test_get_access_token_domain_mismatch_with_dict_state():
    """Test domain mismatch works when state store returns plain dict (stateless cookie store)."""
    session_data = {
        "user": {"sub": "user123"},
        "domain": "tenant1.auth0.com",
        "token_sets": [{
            "audience": "default",
            "access_token": "token123",
            "expires_at": int(time.time()) + 500
        }],
        "internal": {"sid": "123", "created_at": int(time.time())}
    }

    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = session_data

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

    with pytest.raises(AccessTokenError) as exc:
        await client.get_access_token(store_options={"request": {}})
    assert exc.value.code == AccessTokenErrorCode.DOMAIN_MISMATCH


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
async def test_get_access_token_for_connection_domain_mismatch():
    """Test that get_access_token_for_connection raises error on domain mismatch."""
    session_data = StateData(
        user={"sub": "user123"},
        domain="tenant1.auth0.com",
        token_sets=[],
        connection_token_sets=[{
            "connection": "my_connection",
            "audience": "default",
            "access_token": "conn_token",
            "login_hint": "hint",
            "expires_at": int(time.time()) + 500
        }],
        internal={"sid": "123", "created_at": int(time.time())}
    )

    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = session_data

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

    with pytest.raises(AccessTokenForConnectionError) as exc:
        await client.get_access_token_for_connection(
            {"connection": "my_connection"},
            store_options={"request": {}}
        )
    assert exc.value.code == AccessTokenForConnectionErrorCode.DOMAIN_MISMATCH


@pytest.mark.asyncio
async def test_get_access_token_legacy_session_rejected_in_resolver_mode():
    """Test that sessions without domain field raise MISSING_SESSION_DOMAIN in resolver mode."""
    session_data = {
        "user": {"sub": "user123"},
        "token_sets": [{
            "audience": "default",
            "access_token": "token123",
            "expires_at": int(time.time()) + 500
        }],
        "internal": {"sid": "123", "created_at": int(time.time())}
        # No "domain" field — legacy session
    }

    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = session_data

    async def domain_resolver(context):
        return "tenant1.auth0.com"

    client = ServerClient(
        domain=domain_resolver,
        client_id="test_client",
        client_secret="test_secret",
        transaction_store=AsyncMock(),
        state_store=mock_state_store,
        secret="test_secret_key_32_chars_long!!",
    )

    with pytest.raises(AccessTokenError) as exc:
        await client.get_access_token(store_options={"request": {}})
    assert exc.value.code == AccessTokenErrorCode.MISSING_SESSION_DOMAIN


@pytest.mark.asyncio
async def test_get_access_token_for_connection_legacy_session_rejected():
    """Test that sessions without domain field raise MISSING_SESSION_DOMAIN in resolver mode."""
    session_data = {
        "user": {"sub": "user123"},
        "connection_token_sets": [{
            "connection": "my_connection",
            "access_token": "conn_token",
            "expires_at": int(time.time()) + 500
        }],
        "internal": {"sid": "123", "created_at": int(time.time())}
        # No "domain" field — legacy session
    }

    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = session_data

    async def domain_resolver(context):
        return "tenant1.auth0.com"

    client = ServerClient(
        domain=domain_resolver,
        client_id="test_client",
        client_secret="test_secret",
        transaction_store=AsyncMock(),
        state_store=mock_state_store,
        secret="test_secret_key_32_chars_long!!",
    )

    with pytest.raises(AccessTokenForConnectionError) as exc:
        await client.get_access_token_for_connection(
            {"connection": "my_connection"},
            store_options={"request": {}}
        )
    assert exc.value.code == AccessTokenForConnectionErrorCode.MISSING_SESSION_DOMAIN


@pytest.mark.asyncio
async def test_get_access_token_for_connection_domain_mismatch_with_dict_state():
    """Test domain mismatch works when state store returns plain dict (stateless cookie store)."""
    session_data = {
        "user": {"sub": "user123"},
        "domain": "tenant1.auth0.com",
        "connection_token_sets": [{
            "connection": "my_connection",
            "access_token": "conn_token",
            "expires_at": int(time.time()) + 500
        }],
        "internal": {"sid": "123", "created_at": int(time.time())}
    }

    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = session_data

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

    with pytest.raises(AccessTokenForConnectionError) as exc:
        await client.get_access_token_for_connection(
            {"connection": "my_connection"},
            store_options={"request": {}}
        )
    assert exc.value.code == AccessTokenForConnectionErrorCode.DOMAIN_MISMATCH


@pytest.mark.asyncio
async def test_start_link_user_rejects_legacy_session_in_resolver_mode(mocker):
    """Test that start_link_user rejects sessions without domain in resolver mode."""
    async def domain_resolver(context):
        return "tenant1.auth0.com"

    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = {
        "id_token": "existing_id_token",
        "user": {"sub": "user123"}
        # No "domain" field — legacy session
    }

    client = ServerClient(
        domain=domain_resolver,
        client_id="test_client",
        client_secret="test_secret",
        transaction_store=AsyncMock(),
        state_store=mock_state_store,
        secret="test_secret_key_32_chars_long!!",
    )

    with pytest.raises(StartLinkUserError):
        await client.start_link_user(
            options={"connection": "google-oauth2"},
            store_options={"request": {}}
        )


@pytest.mark.asyncio
async def test_start_unlink_user_rejects_legacy_session_in_resolver_mode(mocker):
    """Test that start_unlink_user rejects sessions without domain in resolver mode."""
    async def domain_resolver(context):
        return "tenant1.auth0.com"

    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = {
        "id_token": "existing_id_token",
        "user": {"sub": "user123"}
        # No "domain" field — legacy session
    }

    client = ServerClient(
        domain=domain_resolver,
        client_id="test_client",
        client_secret="test_secret",
        transaction_store=AsyncMock(),
        state_store=mock_state_store,
        secret="test_secret_key_32_chars_long!!",
    )

    with pytest.raises(StartLinkUserError):
        await client.start_unlink_user(
            options={"connection": "google-oauth2"},
            store_options={"request": {}}
        )


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
    mock_jwt_decode = mocker.patch("jwt.decode", return_value={
        "events": {"http://schemas.openid.net/event/backchannel-logout": {}},
        "iss": "https://auth0.local",
        "sub": "user_sub",
        "sid": "session_id_123"
    })

    await client.handle_backchannel_logout("some_logout_token")

    # Verify audience is passed to jwt.decode
    call_kwargs = mock_jwt_decode.call_args[1]
    assert call_kwargs["audience"] == "client_id"

    # iss is always included in claims for issuer-scoped deletion
    mock_state_store.delete_by_logout_token.assert_awaited_once_with(
        {"sub": "user_sub", "sid": "session_id_123", "iss": "https://auth0.local"},
        None
    )


@pytest.mark.asyncio
async def test_backchannel_logout_mcd_known_domain(mocker):
    """Test that backchannel logout works in MCD mode when domain is in cache."""
    async def domain_resolver(context):
        return "tenant1.auth0.com"

    mock_state_store = AsyncMock()

    client = ServerClient(
        domain=domain_resolver,
        client_id="test_client",
        client_secret="test_secret",
        state_store=mock_state_store,
        secret="test_secret_key_32_chars_long!!",
    )

    # Pre-populate the discovery cache (simulates a prior login)
    client._discovery_cache["tenant1.auth0.com"] = {
        "metadata": {
            "issuer": "https://tenant1.auth0.com/",
            "jwks_uri": "https://tenant1.auth0.com/.well-known/jwks.json"
        },
        "jwks": {"keys": [{"kty": "RSA", "kid": "test-key"}]},
        "expires_at": time.time() + 600
    }

    # Mock the unverified decode to extract issuer
    mocker.patch("jwt.decode", return_value={
        "iss": "https://tenant1.auth0.com/",
        "events": {"http://schemas.openid.net/event/backchannel-logout": {}},
        "sub": "user123",
        "sid": "session123"
    })

    mocker.patch.object(
        client, "_get_jwks_cached",
        return_value={"keys": [{"kty": "RSA", "kid": "test-key"}]}
    )

    mock_verify = mocker.patch.object(client, "_verify_and_decode_jwt", return_value={
        "iss": "https://tenant1.auth0.com/",
        "events": {"http://schemas.openid.net/event/backchannel-logout": {}},
        "sub": "user123",
        "sid": "session123"
    })

    await client.handle_backchannel_logout("some_logout_token")

    # Verify audience is passed to JWT verification
    mock_verify.assert_awaited_once()
    call_kwargs = mock_verify.call_args[1]
    assert call_kwargs["audience"] == "test_client"

    # In resolver mode, iss should be included for issuer-scoped deletion
    mock_state_store.delete_by_logout_token.assert_awaited_once_with(
        {"sub": "user123", "sid": "session123", "iss": "https://tenant1.auth0.com/"},
        None
    )


@pytest.mark.asyncio
async def test_backchannel_logout_mcd_iss_mismatch(mocker):
    """Test that backchannel logout rejects token when iss does not match resolved domain."""
    async def domain_resolver(context):
        return "tenant1.auth0.com"

    mock_state_store = AsyncMock()

    client = ServerClient(
        domain=domain_resolver,
        client_id="test_client",
        client_secret="test_secret",
        state_store=mock_state_store,
        secret="test_secret_key_32_chars_long!!",
    )

    # Mock jwt.decode to return a token with a DIFFERENT issuer
    mocker.patch("jwt.decode", return_value={
        "iss": "https://attacker.evil.com/",
        "events": {"http://schemas.openid.net/event/backchannel-logout": {}},
        "sub": "user123",
        "sid": "session123"
    })

    # _verify_and_decode_jwt should NOT be called — rejection happens before signature check
    mock_verify = mocker.patch.object(client, "_verify_and_decode_jwt")

    with pytest.raises(BackchannelLogoutError, match="Logout token issuer does not match the resolved domain"):
        await client.handle_backchannel_logout("malicious_logout_token")

    # Signature verification must not have been reached
    mock_verify.assert_not_awaited()

    # State store must not have been touched
    mock_state_store.delete_by_logout_token.assert_not_awaited()


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
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/token"}
    )

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
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/token"}
    )

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
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/token"}
    )

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
        client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/token"}
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
        client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/token"}
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
        client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/token"}
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
        client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/token"}
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
async def test_get_token_by_refresh_token_mfa_required_raises_mfa_required_error(mocker):
    """get_token_by_refresh_token raises MfaRequiredError (not ApiError) with encrypted token."""
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        secret="a-test-secret-with-enough-length",
    )
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/token"}
    )

    fail_response = AsyncMock()
    fail_response.status_code = 403
    fail_response.json = MagicMock(return_value={
        "error": "mfa_required",
        "error_description": "MFA required",
        "mfa_token": "raw_server_mfa_token",
    })
    mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=fail_response)

    with pytest.raises(MfaRequiredError) as exc:
        await client.get_token_by_refresh_token({"refresh_token": "rt_abc"})

    assert exc.value.mfa_token is not None
    assert exc.value.mfa_token != "raw_server_mfa_token"
    decrypted = client._mfa_client.decrypt_mfa_token(exc.value.mfa_token)
    assert decrypted.mfa_token == "raw_server_mfa_token"


# =============================================================================
# Connected Accounts Tests (My Account Client)
# =============================================================================


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

@pytest.mark.asyncio
@pytest.mark.parametrize("take", ["not_an_integer", 21.3, -5, 0])
async def test_list_connected_accounts__with_invalid_take_param(mocker, take):
    # Setup
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        secret="some-secret"
    )
    mock_my_account_client = AsyncMock(MyAccountClient)
    mocker.patch.object(client, "_my_account_client", mock_my_account_client)

    # Act
    with pytest.raises(InvalidArgumentError) as exc:
        await client.list_connected_accounts(
            connection="<connection>",
            from_param="<from_param>",
            take=take
        )

    # Assert
    assert "The 'take' parameter must be a positive integer." in str(exc.value)
    mock_my_account_client.list_connected_accounts.assert_not_awaited()

@pytest.mark.asyncio
async def test_list_connected_accounts_gets_access_token_and_calls_my_account(mocker):
    # Setup
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        secret="some-secret"
    )
    mock_get_access_token = AsyncMock(return_value="<access_token>")
    mocker.patch.object(client, "get_access_token", mock_get_access_token)
    mock_my_account_client = AsyncMock(MyAccountClient)
    mocker.patch.object(client, "_my_account_client", mock_my_account_client)
    mocker.patch.object(mock_my_account_client, "audience", "https://auth0.local/me/")
    expected_response= ListConnectedAccountsResponse(
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

    mock_my_account_client.list_connected_accounts.return_value = expected_response

    # Act
    response = await client.list_connected_accounts(
        connection="<connection>",
        from_param="<from_param>",
        take=2
    )

    # Assert
    assert response == expected_response
    mock_get_access_token.assert_awaited_with(
        audience="https://auth0.local/me/",
        scope="read:me:connected_accounts",
        store_options=ANY
    )
    mock_my_account_client.list_connected_accounts.assert_awaited_with(
        access_token="<access_token>",
        connection="<connection>",
        from_param="<from_param>",
        take=2
    )

@pytest.mark.asyncio
async def test_delete_connected_account_gets_access_token_and_calls_my_account(mocker):
    # Setup
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        secret="some-secret"
    )
    mock_get_access_token = AsyncMock(return_value="<access_token>")
    mocker.patch.object(client, "get_access_token", mock_get_access_token)
    mock_my_account_client = AsyncMock(MyAccountClient)
    mocker.patch.object(client, "_my_account_client", mock_my_account_client)
    mocker.patch.object(mock_my_account_client, "audience", "https://auth0.local/me/")

    # Act
    await client.delete_connected_account(connected_account_id="<id>")

    # Assert
    mock_get_access_token.assert_awaited_with(
        audience="https://auth0.local/me/",
        scope="delete:me:connected_accounts",
        store_options=ANY
    )
    mock_my_account_client.delete_connected_account.assert_awaited_with(
        access_token="<access_token>",
        connected_account_id="<id>"
    )

@pytest.mark.asyncio
async def test_delete_connected_account_with_empty_connected_account_id(mocker):
    # Setup
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        secret="some-secret"
    )
    mock_my_account_client = AsyncMock(MyAccountClient)
    mocker.patch.object(client, "_my_account_client", mock_my_account_client)

    # Act
    with pytest.raises(MissingRequiredArgumentError) as exc:
        await client.delete_connected_account(connected_account_id=None)

    # Assert
    assert "connected_account_id" in str(exc.value)
    mock_my_account_client.delete_connected_account.assert_not_awaited()

@pytest.mark.asyncio
async def test_list_connected_account_connections_gets_access_token_and_calls_my_account(mocker):
    # Setup
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        secret="some-secret"
    )
    mock_get_access_token = AsyncMock(return_value="<access_token>")
    mocker.patch.object(client, "get_access_token", mock_get_access_token)
    mock_my_account_client = AsyncMock(MyAccountClient)
    mocker.patch.object(client, "_my_account_client", mock_my_account_client)
    mocker.patch.object(mock_my_account_client, "audience", "https://auth0.local/me/")
    expected_response= ListConnectedAccountConnectionsResponse(
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

    mock_my_account_client.list_connected_account_connections.return_value = expected_response

    # Act
    response = await client.list_connected_account_connections(
        from_param="<from_param>",
        take=2
    )

    # Assert
    assert response == expected_response
    mock_get_access_token.assert_awaited_with(
        audience="https://auth0.local/me/",
        scope="read:me:connected_accounts",
        store_options=ANY
    )
    mock_my_account_client.list_connected_account_connections.assert_awaited_with(
        access_token="<access_token>",
        from_param="<from_param>",
        take=2
    )

@pytest.mark.asyncio
@pytest.mark.parametrize("take", ["not_an_integer", 21.3, -5, 0])
async def test_list_connected_account_connections_with_invalid_take_param(mocker, take):
    # Setup
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        secret="some-secret"
    )
    mock_my_account_client = AsyncMock(MyAccountClient)
    mocker.patch.object(client, "_my_account_client", mock_my_account_client)

    # Act
    with pytest.raises(InvalidArgumentError) as exc:
        await client.list_connected_account_connections(
            from_param="<from_param>",
            take=take
        )

    # Assert
    assert "The 'take' parameter must be a positive integer." in str(exc.value)
    mock_my_account_client.list_connected_account_connections.assert_not_awaited()

# =============================================================================
# Custom Token Exchange Tests
# =============================================================================

@pytest.mark.asyncio
async def test_custom_token_exchange_success(mocker):
    """Test successful token exchange with basic parameters."""
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

    # Mock OIDC metadata
    mocker.patch.object(
        client,
        "_fetch_oidc_metadata",
        return_value={"token_endpoint": "https://auth0.local/oauth/token"}
    )
    # Mock httpx response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "access_token": "exchanged_access_token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "read:data",
        "issued_token_type": "urn:ietf:params:oauth:token-type:access_token"
    }
    mock_response.headers.get.return_value = "application/json"

    mock_httpx_client = AsyncMock()
    mock_httpx_client.__aenter__.return_value = mock_httpx_client
    mock_httpx_client.__aexit__.return_value = None
    mock_httpx_client.post.return_value = mock_response

    mocker.patch("httpx.AsyncClient", return_value=mock_httpx_client)

    # Act
    options = CustomTokenExchangeOptions(
        subject_token="custom-token-123",
        subject_token_type="urn:acme:mcp-token",
        audience="https://api.example.com",
        scope="read:data"
    )
    result = await client.custom_token_exchange(options)

    # Assert
    assert result.access_token == "exchanged_access_token"
    assert result.token_type == "Bearer"
    assert result.expires_in == 3600
    assert result.scope == "read:data"
    assert result.issued_token_type == "urn:ietf:params:oauth:token-type:access_token"

    # Verify the request was made correctly
    mock_httpx_client.post.assert_called_once()
    call_args = mock_httpx_client.post.call_args
    assert call_args[0][0] == "https://auth0.local/oauth/token"
    assert call_args[1]["data"]["grant_type"] == "urn:ietf:params:oauth:grant-type:token-exchange"
    assert call_args[1]["data"]["subject_token"] == "custom-token-123"
    assert call_args[1]["data"]["subject_token_type"] == "urn:acme:mcp-token"
    assert call_args[1]["data"]["audience"] == "https://api.example.com"
    assert call_args[1]["data"]["scope"] == "read:data"


@pytest.mark.asyncio
async def test_custom_token_exchange_with_actor_token(mocker):
    """Test token exchange with actor token (delegation scenario)."""
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

    mocker.patch.object(
        client,
        "_fetch_oidc_metadata",
        return_value={"token_endpoint": "https://auth0.local/oauth/token"}
    )

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "access_token": "delegated_token",
        "token_type": "Bearer",
        "expires_in": 1800
    }
    mock_response.headers.get.return_value = "application/json"

    mock_httpx_client = AsyncMock()
    mock_httpx_client.__aenter__.return_value = mock_httpx_client
    mock_httpx_client.__aexit__.return_value = None
    mock_httpx_client.post.return_value = mock_response

    mocker.patch("httpx.AsyncClient", return_value=mock_httpx_client)

    # Act
    options = CustomTokenExchangeOptions(
        subject_token="user-token",
        subject_token_type="urn:ietf:params:oauth:token-type:access_token",
        actor_token="service-token",
        actor_token_type="urn:ietf:params:oauth:token-type:access_token"
    )
    result = await client.custom_token_exchange(options)

    # Assert
    assert result.access_token == "delegated_token"

    # Verify actor params were sent
    call_args = mock_httpx_client.post.call_args
    assert call_args[1]["data"]["actor_token"] == "service-token"
    assert call_args[1]["data"]["actor_token_type"] == "urn:ietf:params:oauth:token-type:access_token"


@pytest.mark.asyncio
async def test_custom_token_exchange_with_organization(mocker):
    """Test token exchange with organization parameter."""
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

    mocker.patch.object(
        client,
        "_fetch_oidc_metadata",
        return_value={"token_endpoint": "https://auth0.local/oauth/token"}
    )

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "access_token": "org_scoped_token",
        "token_type": "Bearer",
        "expires_in": 3600
    }
    mock_response.headers.get.return_value = "application/json"

    mock_httpx_client = AsyncMock()
    mock_httpx_client.__aenter__.return_value = mock_httpx_client
    mock_httpx_client.__aexit__.return_value = None
    mock_httpx_client.post.return_value = mock_response

    mocker.patch("httpx.AsyncClient", return_value=mock_httpx_client)

    # Act
    options = CustomTokenExchangeOptions(
        subject_token="custom-token",
        subject_token_type="urn:acme:mcp-token",
        organization="org_abc1234"
    )
    result = await client.custom_token_exchange(options)

    # Assert
    assert result.access_token == "org_scoped_token"

    # Verify organization param was sent
    call_args = mock_httpx_client.post.call_args
    assert call_args[1]["data"]["organization"] == "org_abc1234"


@pytest.mark.asyncio
async def test_custom_token_exchange_empty_token():
    """Test that empty/whitespace tokens are rejected."""
    # Setup
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="some-secret"
    )

    # Act & Assert - empty token
    with pytest.raises(CustomTokenExchangeError) as exc:
        await client.custom_token_exchange(
            CustomTokenExchangeOptions(
                subject_token="   ",
                subject_token_type="urn:acme:mcp-token"
            )
        )
    assert exc.value.code == CustomTokenExchangeErrorCode.INVALID_TOKEN_FORMAT
    assert "empty or whitespace" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_custom_token_exchange_bearer_prefix():
    """Test that tokens with 'Bearer ' prefix are rejected."""
    # Setup
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="some-secret"
    )

    # Act & Assert
    with pytest.raises(CustomTokenExchangeError) as exc:
        await client.custom_token_exchange(
            CustomTokenExchangeOptions(
                subject_token="Bearer abc123",
                subject_token_type="urn:ietf:params:oauth:token-type:access_token"
            )
        )
    assert exc.value.code == CustomTokenExchangeErrorCode.INVALID_TOKEN_FORMAT
    assert "Bearer" in str(exc.value)


@pytest.mark.asyncio
async def test_custom_token_exchange_missing_actor_token_type():
    """Test that actor_token_type is required when actor_token is provided."""
    # Setup
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="some-secret"
    )

    # Act & Assert
    with pytest.raises(CustomTokenExchangeError) as exc:
        await client.custom_token_exchange(
            CustomTokenExchangeOptions(
                subject_token="token",
                subject_token_type="urn:acme:token",
                actor_token="actor-token",
                actor_token_type=None
            )
        )
    assert exc.value.code == CustomTokenExchangeErrorCode.MISSING_ACTOR_TOKEN_TYPE
    assert "actor_token_type" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_custom_token_exchange_missing_actor_token():
    """Test that actor_token is required when actor_token_type is provided."""
    # Setup
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="some-secret"
    )

    # Act & Assert
    with pytest.raises(CustomTokenExchangeError) as exc:
        await client.custom_token_exchange(
            CustomTokenExchangeOptions(
                subject_token="token",
                subject_token_type="urn:acme:token",
                actor_token=None,
                actor_token_type="urn:ietf:params:oauth:token-type:id_token"
            )
        )
    assert exc.value.code == CustomTokenExchangeErrorCode.MISSING_ACTOR_TOKEN
    assert "actor_token" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_custom_token_exchange_empty_subject_token_type():
    """Test that empty/whitespace subject_token_type is rejected locally."""
    # Setup
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="some-secret"
    )

    # Act & Assert
    with pytest.raises(CustomTokenExchangeError) as exc:
        await client.custom_token_exchange(
            CustomTokenExchangeOptions(
                subject_token="token",
                subject_token_type="   "
            )
        )
    assert exc.value.code == CustomTokenExchangeErrorCode.INVALID_TOKEN_FORMAT
    assert "subject_token_type" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_custom_token_exchange_whitespace_actor_token():
    """Test that a whitespace-only actor_token is rejected locally."""
    # Setup
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="some-secret"
    )

    # Act & Assert
    with pytest.raises(CustomTokenExchangeError) as exc:
        await client.custom_token_exchange(
            CustomTokenExchangeOptions(
                subject_token="token",
                subject_token_type="urn:acme:token",
                actor_token="   ",
                actor_token_type="urn:ietf:params:oauth:token-type:access_token"
            )
        )
    assert exc.value.code == CustomTokenExchangeErrorCode.INVALID_TOKEN_FORMAT
    assert "actor_token" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_custom_token_exchange_api_error_400(mocker):
    """Test handling of 400 error from Auth0."""
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

    mocker.patch.object(
        client,
        "_fetch_oidc_metadata",
        return_value={"token_endpoint": "https://auth0.local/oauth/token"}
    )

    # Mock 400 error response
    mock_response = MagicMock()
    mock_response.status_code = 400
    mock_response.json.return_value = {
        "error": "invalid_grant",
        "error_description": "Subject token is invalid"
    }
    mock_response.headers.get.return_value = "application/json"

    mock_httpx_client = AsyncMock()
    mock_httpx_client.__aenter__.return_value = mock_httpx_client
    mock_httpx_client.__aexit__.return_value = None
    mock_httpx_client.post.return_value = mock_response

    mocker.patch("httpx.AsyncClient", return_value=mock_httpx_client)

    # Act & Assert
    with pytest.raises(CustomTokenExchangeError) as exc:
        await client.custom_token_exchange(
            CustomTokenExchangeOptions(
                subject_token="invalid-token",
                subject_token_type="urn:acme:mcp-token"
            )
        )
    assert exc.value.code == "invalid_grant"
    assert "Subject token is invalid" in str(exc.value)


@pytest.mark.asyncio
async def test_custom_token_exchange_invalid_json_response(mocker):
    """Test handling of non-JSON response from token endpoint."""
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

    mocker.patch.object(
        client,
        "_fetch_oidc_metadata",
        return_value={"token_endpoint": "https://auth0.local/oauth/token"}
    )

    # Mock response with invalid JSON
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.side_effect = json.JSONDecodeError("msg", "doc", 0)
    mock_response.headers.get.return_value = "application/json"

    mock_httpx_client = AsyncMock()
    mock_httpx_client.__aenter__.return_value = mock_httpx_client
    mock_httpx_client.__aexit__.return_value = None
    mock_httpx_client.post.return_value = mock_response

    mocker.patch("httpx.AsyncClient", return_value=mock_httpx_client)

    # Act & Assert
    with pytest.raises(CustomTokenExchangeError) as exc:
        await client.custom_token_exchange(
            CustomTokenExchangeOptions(
                subject_token="token",
                subject_token_type="urn:acme:mcp-token"
            )
        )
    assert exc.value.code == CustomTokenExchangeErrorCode.INVALID_RESPONSE
    assert "parse" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_custom_token_exchange_missing_token_endpoint(mocker):
    """Test error when token endpoint is missing from OIDC metadata."""
    # Setup
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="some-secret"
    )

    # Mock metadata without token_endpoint
    mocker.patch.object(
        client,
        "_fetch_oidc_metadata",
        return_value={"authorization_endpoint": "https://auth0.local/authorize"}
    )

    # Act & Assert
    with pytest.raises(ApiError) as exc:
        await client.custom_token_exchange(
            CustomTokenExchangeOptions(
                subject_token="token",
                subject_token_type="urn:acme:mcp-token"
            )
        )
    assert exc.value.code == "configuration_error"
    assert "token endpoint" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_custom_token_exchange_with_authorization_params(mocker):
    """Test that additional authorization_params are passed through."""
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

    mocker.patch.object(
        client,
        "_fetch_oidc_metadata",
        return_value={"token_endpoint": "https://auth0.local/oauth/token"}
    )

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "access_token": "token",
        "token_type": "Bearer",
        "expires_in": 3600
    }
    mock_response.headers.get.return_value = "application/json"

    mock_httpx_client = AsyncMock()
    mock_httpx_client.__aenter__.return_value = mock_httpx_client
    mock_httpx_client.__aexit__.return_value = None
    mock_httpx_client.post.return_value = mock_response

    mocker.patch("httpx.AsyncClient", return_value=mock_httpx_client)

    # Act
    await client.custom_token_exchange(
        CustomTokenExchangeOptions(
            subject_token="token",
            subject_token_type="urn:acme:mcp-token",
            authorization_params={"custom_param": "custom_value"}
        )
    )

    # Assert
    call_args = mock_httpx_client.post.call_args
    assert call_args[1]["data"]["custom_param"] == "custom_value"


@pytest.mark.asyncio
async def test_custom_token_exchange_forbidden_params_filtered(mocker):
    """Test that forbidden params cannot be overridden."""
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

    mocker.patch.object(
        client,
        "_fetch_oidc_metadata",
        return_value={"token_endpoint": "https://auth0.local/oauth/token"}
    )

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "access_token": "token",
        "token_type": "Bearer",
        "expires_in": 3600
    }
    mock_response.headers.get.return_value = "application/json"

    mock_httpx_client = AsyncMock()
    mock_httpx_client.__aenter__.return_value = mock_httpx_client
    mock_httpx_client.__aexit__.return_value = None
    mock_httpx_client.post.return_value = mock_response

    mocker.patch("httpx.AsyncClient", return_value=mock_httpx_client)

    # Act
    await client.custom_token_exchange(
        CustomTokenExchangeOptions(
            subject_token="token",
            subject_token_type="urn:acme:mcp-token",
            authorization_params={
                "grant_type": "malicious_grant",  # Should be filtered
                "client_id": "malicious_client",  # Should be filtered
                "allowed_param": "value"  # Should be allowed
            }
        )
    )

    # Assert
    call_args = mock_httpx_client.post.call_args
    assert call_args[1]["data"]["grant_type"] == "urn:ietf:params:oauth:grant-type:token-exchange"
    assert call_args[1]["data"]["client_id"] == "<client_id>"
    assert call_args[1]["data"]["allowed_param"] == "value"


# Delegation Support


@pytest.mark.asyncio
async def test_custom_token_exchange_surfaces_act_claim(mocker):
    """Actor claim from the ID token is exposed on the response, nesting preserved."""
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="some-secret"
    )

    mocker.patch.object(
        client, "_fetch_oidc_metadata",
        return_value={
            "token_endpoint": "https://auth0.local/oauth/token",
            "issuer": "https://auth0.local/",
        }
    )
    mocker.patch.object(client, "_get_jwks_cached", return_value={"keys": []})
    mocker.patch.object(client, "_verify_and_decode_jwt", return_value={
        "sub": "user123",
        "iss": "https://auth0.local/",
        "act": {"sub": "agent|abc", "act": {"sub": "svc|xyz"}},
    })

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "access_token": "delegated_token",
        "token_type": "Bearer",
        "expires_in": 1800,
        "id_token": "header.payload.sig",
    }
    mock_response.headers.get.return_value = "application/json"

    mock_httpx_client = AsyncMock()
    mock_httpx_client.__aenter__.return_value = mock_httpx_client
    mock_httpx_client.__aexit__.return_value = None
    mock_httpx_client.post.return_value = mock_response
    mocker.patch("httpx.AsyncClient", return_value=mock_httpx_client)

    result = await client.custom_token_exchange(CustomTokenExchangeOptions(
        subject_token="user-token",
        subject_token_type="urn:ietf:params:oauth:token-type:access_token",
        actor_token="service-token",
        actor_token_type="urn:ietf:params:oauth:token-type:access_token",
    ))

    assert result.act == {"sub": "agent|abc", "act": {"sub": "svc|xyz"}}
    assert result.act["act"]["sub"] == "svc|xyz"


@pytest.mark.asyncio
async def test_custom_token_exchange_act_none_when_no_id_token(mocker):
    """A response without an id_token leaves act as None (decode path skipped)."""
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="some-secret"
    )

    mocker.patch.object(
        client, "_fetch_oidc_metadata",
        return_value={"token_endpoint": "https://auth0.local/oauth/token"}
    )

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "access_token": "opaque_token",
        "token_type": "Bearer",
        "expires_in": 1800,
    }
    mock_response.headers.get.return_value = "application/json"

    mock_httpx_client = AsyncMock()
    mock_httpx_client.__aenter__.return_value = mock_httpx_client
    mock_httpx_client.__aexit__.return_value = None
    mock_httpx_client.post.return_value = mock_response
    mocker.patch("httpx.AsyncClient", return_value=mock_httpx_client)

    result = await client.custom_token_exchange(CustomTokenExchangeOptions(
        subject_token="user-token",
        subject_token_type="urn:ietf:params:oauth:token-type:access_token",
        actor_token="service-token",
        actor_token_type="urn:ietf:params:oauth:token-type:access_token",
    ))

    assert result.act is None


@pytest.mark.asyncio
async def test_custom_token_exchange_act_none_when_id_token_undecodable(mocker):
    """A present-but-undecodable id_token leaves act None without failing the exchange."""
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="some-secret"
    )

    mocker.patch.object(
        client, "_fetch_oidc_metadata",
        return_value={
            "token_endpoint": "https://auth0.local/oauth/token",
            "issuer": "https://auth0.local/",
        }
    )
    mocker.patch.object(client, "_get_jwks_cached", return_value={"keys": []})
    # No matching JWKS key -> _verify_and_decode_jwt raises; must not bubble up.
    mocker.patch.object(
        client, "_verify_and_decode_jwt",
        side_effect=ValueError("No matching key found in JWKS for kid: abc")
    )

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "access_token": "delegated_token",
        "token_type": "Bearer",
        "expires_in": 1800,
        "id_token": "header.payload.sig",
    }
    mock_response.headers.get.return_value = "application/json"

    mock_httpx_client = AsyncMock()
    mock_httpx_client.__aenter__.return_value = mock_httpx_client
    mock_httpx_client.__aexit__.return_value = None
    mock_httpx_client.post.return_value = mock_response
    mocker.patch("httpx.AsyncClient", return_value=mock_httpx_client)

    result = await client.custom_token_exchange(CustomTokenExchangeOptions(
        subject_token="user-token",
        subject_token_type="urn:ietf:params:oauth:token-type:access_token",
        actor_token="service-token",
        actor_token_type="urn:ietf:params:oauth:token-type:access_token",
    ))

    # Exchange still succeeds; only the act enrichment is skipped.
    assert result.access_token == "delegated_token"
    assert result.act is None


@pytest.mark.asyncio
async def test_custom_token_exchange_act_dropped_on_issuer_mismatch(mocker):
    """An id_token from an unexpected issuer does not surface its act claim."""
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="some-secret"
    )

    mocker.patch.object(
        client, "_fetch_oidc_metadata",
        return_value={
            "token_endpoint": "https://auth0.local/oauth/token",
            "issuer": "https://auth0.local/",
        }
    )
    mocker.patch.object(client, "_get_jwks_cached", return_value={"keys": []})
    mocker.patch.object(client, "_verify_and_decode_jwt", return_value={
        "sub": "user123",
        "iss": "https://evil.example.com/",
        "act": {"sub": "agent|abc"},
    })

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "access_token": "delegated_token",
        "token_type": "Bearer",
        "expires_in": 1800,
        "id_token": "header.payload.sig",
    }
    mock_response.headers.get.return_value = "application/json"

    mock_httpx_client = AsyncMock()
    mock_httpx_client.__aenter__.return_value = mock_httpx_client
    mock_httpx_client.__aexit__.return_value = None
    mock_httpx_client.post.return_value = mock_response
    mocker.patch("httpx.AsyncClient", return_value=mock_httpx_client)

    result = await client.custom_token_exchange(CustomTokenExchangeOptions(
        subject_token="user-token",
        subject_token_type="urn:ietf:params:oauth:token-type:access_token",
        actor_token="service-token",
        actor_token_type="urn:ietf:params:oauth:token-type:access_token",
    ))

    assert result.act is None


# =============================================================================
# Login with Custom Token Exchange Tests
# =============================================================================

@pytest.mark.asyncio
async def test_login_with_custom_token_exchange_success(mocker):
    """Test successful login with custom token exchange."""
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

    mocker.patch.object(
        client,
        "_fetch_oidc_metadata",
        return_value={
            "token_endpoint": "https://auth0.local/oauth/token",
            "issuer": "https://auth0.local/",
        }
    )

    # Mock JWKS fetch
    mocker.patch.object(
        client,
        "_get_jwks_cached",
        return_value={"keys": []}
    )

    # Mock token exchange response with ID token
    id_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwibmFtZSI6IkpvaG4gRG9lIiwic2lkIjoic2Vzc2lvbjEyMyJ9.fake"
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "access_token": "exchanged_token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": id_token,
        "refresh_token": "refresh_token_123"
    }
    mock_response.headers.get.return_value = "application/json"

    mock_httpx_client = AsyncMock()
    mock_httpx_client.__aenter__.return_value = mock_httpx_client
    mock_httpx_client.__aexit__.return_value = None
    mock_httpx_client.post.return_value = mock_response

    mocker.patch("httpx.AsyncClient", return_value=mock_httpx_client)

    # Mock ID token verification (signature + decode)
    mocker.patch.object(client, "_verify_and_decode_jwt", return_value={
        "sub": "user123",
        "name": "John Doe",
        "sid": "session123",
        "iss": "https://auth0.local/"
    })

    # Act
    result = await client.login_with_custom_token_exchange(
        LoginWithCustomTokenExchangeOptions(
            subject_token="custom-token",
            subject_token_type="urn:acme:mcp-token",
            audience="https://api.example.com"
        )
    )

    # Assert
    assert result.state_data is not None
    assert result.state_data["user"]["sub"] == "user123"
    assert result.state_data["user"]["name"] == "John Doe"
    assert result.state_data["id_token"] == id_token
    assert result.state_data["refresh_token"] == "refresh_token_123"
    assert len(result.state_data["token_sets"]) == 1
    assert result.state_data["token_sets"][0]["access_token"] == "exchanged_token"
    assert result.state_data["internal"]["sid"] == "session123"

    # Verify state was stored
    mock_state_store.set.assert_awaited_once()


@pytest.mark.asyncio
async def test_login_with_custom_token_exchange_no_id_token(mocker):
    """Test login when no ID token is returned."""
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

    mocker.patch.object(
        client,
        "_fetch_oidc_metadata",
        return_value={"token_endpoint": "https://auth0.local/oauth/token"}
    )

    # Mock token exchange response without ID token
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "access_token": "exchanged_token",
        "token_type": "Bearer",
        "expires_in": 3600
    }
    mock_response.headers.get.return_value = "application/json"

    mock_httpx_client = AsyncMock()
    mock_httpx_client.__aenter__.return_value = mock_httpx_client
    mock_httpx_client.__aexit__.return_value = None
    mock_httpx_client.post.return_value = mock_response

    mocker.patch("httpx.AsyncClient", return_value=mock_httpx_client)

    # Act
    result = await client.login_with_custom_token_exchange(
        LoginWithCustomTokenExchangeOptions(
            subject_token="custom-token",
            subject_token_type="urn:acme:mcp-token"
        )
    )

    # Assert - user should be None, but session should be created
    assert result.state_data["user"] is None
    assert result.state_data["id_token"] is None
    assert len(result.state_data["token_sets"]) == 1
    assert "sid" in result.state_data["internal"]

    # Verify state was stored
    mock_state_store.set.assert_awaited_once()


@pytest.mark.asyncio
async def test_login_with_custom_token_exchange_failure_propagates(mocker):
    """Test that token exchange failures are propagated."""
    # Setup
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="some-secret"
    )

    mocker.patch.object(
        client,
        "_fetch_oidc_metadata",
        return_value={"token_endpoint": "https://auth0.local/oauth/token"}
    )

    # Mock 401 error
    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_response.json.return_value = {
        "error": "unauthorized",
        "error_description": "Invalid credentials"
    }
    mock_response.headers.get.return_value = "application/json"

    mock_httpx_client = AsyncMock()
    mock_httpx_client.__aenter__.return_value = mock_httpx_client
    mock_httpx_client.__aexit__.return_value = None
    mock_httpx_client.post.return_value = mock_response

    mocker.patch("httpx.AsyncClient", return_value=mock_httpx_client)

    # Act & Assert
    with pytest.raises(CustomTokenExchangeError) as exc:
        await client.login_with_custom_token_exchange(
            LoginWithCustomTokenExchangeOptions(
                subject_token="invalid-token",
                subject_token_type="urn:acme:mcp-token"
            )
        )
    assert exc.value.code == "unauthorized"


@pytest.mark.asyncio
async def test_login_with_custom_token_exchange_persists_act_on_user(mocker):
    """The act claim from the ID token is persisted on the session user."""
    mock_state_store = AsyncMock()
    client = ServerClient(
        domain="auth0.local",
        client_id="<client_id>",
        client_secret="<client_secret>",
        state_store=mock_state_store,
        transaction_store=AsyncMock(),
        secret="some-secret"
    )

    mocker.patch.object(
        client, "_fetch_oidc_metadata",
        return_value={
            "token_endpoint": "https://auth0.local/oauth/token",
            "issuer": "https://auth0.local/",
        }
    )
    mocker.patch.object(client, "_get_jwks_cached", return_value={"keys": []})
    mocker.patch.object(client, "_verify_and_decode_jwt", return_value={
        "sub": "user123",
        "iss": "https://auth0.local/",
        "act": {"sub": "agent|abc", "act": {"sub": "svc|xyz"}},
    })

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "access_token": "exchanged_token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": "header.payload.sig",
    }
    mock_response.headers.get.return_value = "application/json"

    mock_httpx_client = AsyncMock()
    mock_httpx_client.__aenter__.return_value = mock_httpx_client
    mock_httpx_client.__aexit__.return_value = None
    mock_httpx_client.post.return_value = mock_response
    mocker.patch("httpx.AsyncClient", return_value=mock_httpx_client)

    result = await client.login_with_custom_token_exchange(
        LoginWithCustomTokenExchangeOptions(
            subject_token="custom-token",
            subject_token_type="urn:acme:mcp-token",
            actor_token="service-token",
            actor_token_type="urn:ietf:params:oauth:token-type:access_token",
        )
    )

    assert result.state_data["user"]["act"] == {"sub": "agent|abc", "act": {"sub": "svc|xyz"}}


def test_state_merge_preserves_user_act_claim():
    """The state merge used on refresh must not drop the user's act claim."""
    state_data = {
        "user": {"sub": "user123", "act": {"sub": "agent|abc"}},
        "id_token": "old.jwt",
        "refresh_token": "rt",
        "token_sets": [{"audience": "aud1", "access_token": "at", "scope": "openid", "expires_at": 0}],
        "internal": {"sid": "s", "created_at": 0},
    }
    # Refresh-token grants do not re-emit the act claim.
    refresh_response = {
        "access_token": "new_at",
        "id_token": "new.jwt",
        "scope": "openid",
        "expires_in": 3600,
    }

    updated = State.update_state_data("aud1", state_data, refresh_response)

    assert updated["user"]["act"] == {"sub": "agent|abc"}


# =============================================================================
# OIDC Metadata and JWKS Fetching Tests
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
    first_fetch_count = fetch_count

    # Second call - should use cache
    result2 = await client._get_oidc_metadata_cached("tenant.auth0.com")
    assert result2 == mock_metadata
    assert fetch_count == first_fetch_count  # Should NOT increment

    # Verify cache contains data
    assert "tenant.auth0.com" in client._discovery_cache
    assert client._discovery_cache["tenant.auth0.com"]["metadata"] == mock_metadata


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
    first_fetch_count = fetch_count

    # Second call - should use cache
    result2 = await client._get_jwks_cached("tenant.auth0.com", mock_metadata)
    assert result2 == mock_jwks
    assert fetch_count == first_fetch_count  # Should NOT increment


@pytest.mark.asyncio
async def test_jwks_cache_size_limit():
    """Test JWKS cache enforces max size limit with LRU eviction."""
    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="test_client",
        client_secret="test_secret",
        secret="test_secret_key_32_chars_long!!",
        transaction_store=AsyncMock(),
        state_store=AsyncMock()
    )

    # Set small cache size for testing
    client._cache_max_entries = 3

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

    assert len(client._discovery_cache) == 3
    assert "domain1.auth0.com" in client._discovery_cache

    # Add one more - should evict oldest (domain1)
    await client._get_jwks_cached("domain4.auth0.com")

    assert len(client._discovery_cache) == 3
    assert "domain1.auth0.com" not in client._discovery_cache  # Evicted
    assert "domain4.auth0.com" in client._discovery_cache


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

    client._cache_max_entries = 2

    async def mock_fetch(domain):
        return {"issuer": f"https://{domain}/"}

    client._fetch_oidc_metadata = mock_fetch

    # Fill cache
    await client._get_oidc_metadata_cached("domain1.auth0.com")
    await client._get_oidc_metadata_cached("domain2.auth0.com")

    assert len(client._discovery_cache) == 2

    # Add third - should evict first
    await client._get_oidc_metadata_cached("domain3.auth0.com")

    assert len(client._discovery_cache) == 2
    assert "domain1.auth0.com" not in client._discovery_cache
    assert "domain3.auth0.com" in client._discovery_cache


# =============================================================================
# Issuer Validation Tests
# =============================================================================


@pytest.mark.asyncio
async def test_complete_login_issuer_validation_success(mocker):
    """Test complete login with valid issuer in ID token."""
    mock_tx_store = AsyncMock()
    mock_tx_store.get.return_value = TransactionData(
        code_verifier="123",
        domain="tenant.auth0.com",
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
        "iss": "https://tenant.auth0.com/",  # Matches metadata issuer
        "aud": "test_client"
    })

    # Should succeed without raising error
    result = await client.complete_interactive_login("http://localhost/callback?code=abc&state=xyz")

    assert result is not None
    assert "state_data" in result


@pytest.mark.asyncio
async def test_complete_login_issuer_mismatch_raises_error(mocker):
    """Test that issuer mismatch in ID token raises IssuerValidationError."""
    mock_tx_store = AsyncMock()
    mock_tx_store.get.return_value = TransactionData(
        code_verifier="123",
        domain="tenant.auth0.com",
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

    # Mock jwt.decode to return claims with a WRONG issuer
    # Our custom normalized issuer validation should catch this mismatch
    mocker.patch("jwt.decode", return_value={
        "sub": "user123",
        "iss": "https://wrong-issuer.auth0.com/",  # Different from expected: https://tenant.auth0.com/
        "aud": "test_client",
        "exp": 9999999999
    })

    # Should raise IssuerValidationError
    with pytest.raises(IssuerValidationError) as exc_info:
        await client.complete_interactive_login("http://localhost/callback?code=abc&state=xyz")

    assert exc_info.value.code == "issuer_validation_error"
    assert "issuer mismatch" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_normalize_url_handles_different_schemes():
    """Test that _normalize_url handles various URL schemes correctly."""
    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="test_client",
        client_secret="test_secret",
        secret="test_secret_key_32_chars_long!!",
        transaction_store=AsyncMock(),
        state_store=AsyncMock()
    )

    # Test domain without scheme
    assert client._normalize_url("auth0.com") == "https://auth0.com"

    # Test domain with https scheme (should remain unchanged)
    assert client._normalize_url("https://auth0.com") == "https://auth0.com"

    # Test domain with http scheme (should convert to https)
    assert client._normalize_url("http://auth0.com") == "https://auth0.com"

    # Test domain with trailing slash (should strip it)
    assert client._normalize_url("https://auth0.com/") == "https://auth0.com"


@pytest.mark.asyncio
async def test_normalize_url_handles_edge_cases():
    """Test that _normalize_url handles edge cases for robust URL comparison.

    This test documents the edge cases that could cause validation failures
    with strict string comparison:
    - Trailing slash differences
    - Case sensitivity
    - HTTP vs HTTPS schemes
    - Missing scheme
    """
    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="test_client",
        client_secret="test_secret",
        secret="test_secret_key_32_chars_long!!",
        transaction_store=AsyncMock(),
        state_store=AsyncMock()
    )

    # Test trailing slash normalization
    assert client._normalize_url("https://auth0.com/") == "https://auth0.com"
    assert client._normalize_url("https://auth0.com") == "https://auth0.com"
    assert client._normalize_url("https://auth0.com/") == client._normalize_url("https://auth0.com")

    # Test case insensitivity
    assert client._normalize_url("HTTPS://AUTH0.COM/") == "https://auth0.com"
    assert client._normalize_url("Https://Auth0.Com") == "https://auth0.com"
    assert client._normalize_url("HTTPS://AUTH0.COM/") == client._normalize_url("https://auth0.com")

    # Test HTTP to HTTPS conversion
    assert client._normalize_url("http://auth0.com") == "https://auth0.com"
    assert client._normalize_url("HTTP://AUTH0.COM/") == "https://auth0.com"

    # Test missing scheme
    assert client._normalize_url("auth0.com") == "https://auth0.com"
    assert client._normalize_url("AUTH0.COM/") == "https://auth0.com"

    # Test empty/None handling
    assert client._normalize_url("") == ""
    assert client._normalize_url(None) is None


# =============================================================================
# MCD Tests : Multiple Issuer Configuration Methods Tests
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
# MCD Tests : Domain Resolver Context Tests
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
    except Exception:  # noqa: S110
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
    except Exception:  # noqa: S110
        pass  # We only care about context being passed
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


@pytest.mark.asyncio
async def test_sync_callable_as_domain_resolver_raises_error():
    """Test that a non-async (sync) callable raises DomainResolverError.

    The SDK always awaits the resolver, so sync callables are not supported.
    Domain resolvers must be async functions.
    """
    def sync_resolver(context):
        return "tenant1.auth0.com"

    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = StateData(
        user={"sub": "user123"},
        domain="tenant1.auth0.com",
        token_sets=[],
        internal={"sid": "123", "created_at": int(time.time())}
    )

    client = ServerClient(
        domain=sync_resolver,
        client_id="test_client",
        client_secret="test_secret",
        transaction_store=AsyncMock(),
        state_store=mock_state_store,
        secret="test_secret_key_32_chars_long!!",
    )

    with pytest.raises(DomainResolverError):
        await client.get_user(store_options={"request": {}})


@pytest.mark.asyncio
async def test_resolver_returns_domain_with_scheme_prefix():
    """Test that domain resolver returning 'https://domain' works with session matching."""
    async def resolver_with_scheme(context):
        return "https://tenant1.auth0.com"

    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = StateData(
        user={"sub": "user123"},
        domain="https://tenant1.auth0.com",
        token_sets=[],
        internal={"sid": "123", "created_at": int(time.time())}
    )

    client = ServerClient(
        domain=resolver_with_scheme,
        client_id="test_client",
        client_secret="test_secret",
        transaction_store=AsyncMock(),
        state_store=mock_state_store,
        secret="test_secret_key_32_chars_long!!",
    )

    user = await client.get_user(store_options={"request": {}})
    assert user is not None
    assert user["sub"] == "user123"


# =============================================================================
# MCD Tests : Domain-specific Session Management Tests
# =============================================================================


@pytest.mark.asyncio
async def test_session_stores_domain(mocker):
    """Test that session stores domain from login (Requirement 5)."""
    mock_tx_store = AsyncMock()
    mock_tx_store.get.return_value = TransactionData(
        code_verifier="123",
        domain="tenant1.auth0.com",
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
    mock_state_store.get.return_value = {"domain": current_domain, "user": {"sub": "user1"}}

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
    # Verify session was deleted (domains match)
    mock_state_store.delete.assert_called_once()


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
        domain=new_domain,
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


# ── MFA Integration Tests ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_server_client_mfa_property():
    """
    The ServerClient should expose an 'mfa' property returning an MfaClient instance.
    """
    mock_secret = "a-test-secret-with-enough-length"
    mock_store = MagicMock()
    mock_store.get = AsyncMock(return_value=None)
    mock_store.set = AsyncMock()
    mock_store.delete = AsyncMock()

    # Patch OIDC metadata
    original_fetch = ServerClient._fetch_oidc_metadata

    async def _fake_fetch(self, domain):
        return {
            "authorization_endpoint": f"https://{domain}/authorize",
            "token_endpoint": f"https://{domain}/oauth/token",
            "end_session_endpoint": f"https://{domain}/v2/logout",
            "backchannel_logout_supported": True,
        }

    ServerClient._fetch_oidc_metadata = _fake_fetch
    try:
        client = ServerClient(
            domain="auth0.local",
            client_id="cid",
            client_secret="csecret",
            secret=mock_secret,
            transaction_store=mock_store,
            state_store=mock_store,
        )
        assert isinstance(client.mfa, MfaClient)
    finally:
        ServerClient._fetch_oidc_metadata = original_fetch


@pytest.mark.asyncio
async def test_server_client_mfa_receives_callable_domain():
    """
    When ServerClient is given a callable domain (MCD), the MfaClient
    should receive that callable — not None or a resolved string.
    """
    mock_secret = "a-test-secret-with-enough-length"
    mock_store = MagicMock()
    mock_store.get = AsyncMock(return_value=None)
    mock_store.set = AsyncMock()
    mock_store.delete = AsyncMock()

    async def my_resolver(context):
        return "tenant-x.auth0.local"

    original_fetch = ServerClient._fetch_oidc_metadata

    async def _fake_fetch(self, domain):
        return {
            "authorization_endpoint": f"https://{domain}/authorize",
            "token_endpoint": f"https://{domain}/oauth/token",
            "end_session_endpoint": f"https://{domain}/v2/logout",
            "backchannel_logout_supported": True,
        }

    ServerClient._fetch_oidc_metadata = _fake_fetch
    try:
        client = ServerClient(
            domain=my_resolver,
            client_id="cid",
            client_secret="csecret",
            secret=mock_secret,
            transaction_store=mock_store,
            state_store=mock_store,
        )
        mfa = client.mfa
        assert isinstance(mfa, MfaClient)
        assert mfa._domain_resolver is my_resolver
        assert mfa._domain is None
    finally:
        ServerClient._fetch_oidc_metadata = original_fetch


@pytest.mark.asyncio
async def test_get_access_token_mfa_required(mocker):
    """
    When get_token_by_refresh_token returns MfaRequiredError,
    get_access_token re-raises it (token is already encrypted by get_token_by_refresh_token).
    """
    mock_secret = "a-test-secret-with-enough-length"
    mock_store = MagicMock()
    mock_store.get = AsyncMock(return_value=None)
    mock_store.set = AsyncMock()
    mock_store.delete = AsyncMock()

    original_fetch = ServerClient._fetch_oidc_metadata

    async def _fake_fetch(self, domain):
        return {
            "authorization_endpoint": f"https://{domain}/authorize",
            "token_endpoint": f"https://{domain}/oauth/token",
            "end_session_endpoint": f"https://{domain}/v2/logout",
            "backchannel_logout_supported": True,
        }

    ServerClient._fetch_oidc_metadata = _fake_fetch
    try:
        client = ServerClient(
            domain="auth0.local",
            client_id="cid",
            client_secret="csecret",
            secret=mock_secret,
            transaction_store=mock_store,
            state_store=mock_store,
        )

        mock_store.get = AsyncMock(return_value={
            "refresh_token": "rt_123",
            "token_sets": [
                {
                    "audience": "default",
                    "access_token": "expired_at",
                    "expires_at": 0,
                }
            ]
        })

        encrypted_token = client._mfa_client._encrypt_mfa_token(
            raw_mfa_token="raw_mfa_token_xyz",
            audience="default",
            scope="",
        )
        mfa_err = MfaRequiredError(
            "Multifactor authentication required",
            mfa_token=encrypted_token,
        )

        mocker.patch.object(client, "get_token_by_refresh_token",
                           new_callable=AsyncMock, side_effect=mfa_err)

        with pytest.raises(MfaRequiredError) as exc:
            await client.get_access_token()

        assert exc.value.mfa_token == encrypted_token
    finally:
        ServerClient._fetch_oidc_metadata = original_fetch


@pytest.mark.asyncio
async def test_get_access_token_mfa_required_with_enroll_requirements(mocker):
    """
    When get_token_by_refresh_token returns MfaRequiredError with mfa_requirements,
    get_access_token re-raises it preserving requirements.
    """
    mock_secret = "a-test-secret-with-enough-length"
    mock_store = MagicMock()
    mock_store.get = AsyncMock(return_value=None)
    mock_store.set = AsyncMock()
    mock_store.delete = AsyncMock()

    original_fetch = ServerClient._fetch_oidc_metadata

    async def _fake_fetch(self, domain):
        return {
            "authorization_endpoint": f"https://{domain}/authorize",
            "token_endpoint": f"https://{domain}/oauth/token",
            "end_session_endpoint": f"https://{domain}/v2/logout",
            "backchannel_logout_supported": True,
        }

    ServerClient._fetch_oidc_metadata = _fake_fetch
    try:
        client = ServerClient(
            domain="auth0.local",
            client_id="cid",
            client_secret="csecret",
            secret=mock_secret,
            transaction_store=mock_store,
            state_store=mock_store,
        )

        mock_store.get = AsyncMock(return_value={
            "refresh_token": "rt_123",
            "token_sets": [
                {
                    "audience": "default",
                    "access_token": "expired_at",
                    "expires_at": 0,
                }
            ]
        })

        requirements = MfaRequirements(
            enroll=[
                {"type": "otp"},
                {"type": "phone"},
                {"type": "push-notification"}
            ]
        )
        encrypted_token = client._mfa_client._encrypt_mfa_token(
            raw_mfa_token="raw_mfa_token_enroll",
            audience="default",
            scope="",
            mfa_requirements=requirements,
        )
        mfa_err = MfaRequiredError(
            "Multifactor authentication required",
            mfa_token=encrypted_token,
            mfa_requirements=requirements,
        )

        mocker.patch.object(client, "get_token_by_refresh_token",
                           new_callable=AsyncMock, side_effect=mfa_err)

        with pytest.raises(MfaRequiredError) as exc:
            await client.get_access_token()

        assert exc.value.mfa_token == encrypted_token
        assert exc.value.mfa_requirements is not None
    finally:
        ServerClient._fetch_oidc_metadata = original_fetch


# =============================================================================
# PASSKEY AUTHENTICATION
# =============================================================================

_PASSKEY_SIGNUP_CHALLENGE_RESPONSE = {
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

_PASSKEY_LOGIN_CHALLENGE_RESPONSE = {
    "auth_session": "session_login_xyz",
    "authn_params_public_key": {
        "challenge": "bG9naW4tY2hhbGxlbmdl",
        "rpId": "auth0.local",
        "timeout": 60000,
        "userVerification": "preferred",
    },
}

_PASSKEY_TOKEN_RESPONSE = {
    "access_token": "at_passkey_123",
    "id_token": "eyJ.test.jwt",
    "token_type": "Bearer",
    "expires_in": 86400,
    "scope": "openid profile",
}

_PASSKEY_TOKEN_RESPONSE_DPOP = {
    "access_token": "at_passkey_dpop_123",
    "id_token": "eyJ.test.jwt",
    "token_type": "DPoP",
    "expires_in": 86400,
    "scope": "openid profile",
}


def _make_passkey_authn_response():
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
async def test_passkey_signup_challenge_success(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = MagicMock(return_value=_PASSKEY_SIGNUP_CHALLENGE_RESPONSE)
    mock_post.return_value = mock_response

    result = await client.passkey_signup_challenge(
        user_profile=PasskeyUserProfile(email="user@example.com", name="Jane Doe"),
        connection="Username-Password-Authentication",
    )

    assert isinstance(result, PasskeySignupChallengeResponse)
    assert result.auth_session == "session_abc123"
    assert result.authn_params_public_key.challenge == "dGVzdC1jaGFsbGVuZ2U"
    assert result.authn_params_public_key.rp.id == "auth0.local"
    assert result.authn_params_public_key.user.display_name == "Jane"
    assert result.authn_params_public_key.pub_key_cred_params[0].alg == -7
    assert result.authn_params_public_key.authenticator_selection.resident_key == "required"

    mock_post.assert_awaited_once()
    args, kwargs = mock_post.call_args
    assert "/passkey/register" in args[0]
    body = kwargs["json"]
    assert body["client_id"] == "test_client_id"
    assert body["client_secret"] == "test_client_secret"
    assert body["user_profile"]["email"] == "user@example.com"
    assert body["user_profile"]["name"] == "Jane Doe"
    assert body["realm"] == "Username-Password-Authentication"


@pytest.mark.asyncio
async def test_passkey_signup_challenge_user_profile_fields(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = MagicMock(return_value=_PASSKEY_SIGNUP_CHALLENGE_RESPONSE)
    mock_post.return_value = mock_response

    await client.passkey_signup_challenge(
        user_profile=PasskeyUserProfile(
            email="u@e.com",
            username="jdoe",
            phone_number="+1234567890",
            given_name="Jane",
            family_name="Doe",
            nickname="jd",
            picture="https://example.com/pic.jpg",
        ),
        user_metadata={"role": "admin"},
        organization="org_123",
    )

    args, kwargs = mock_post.call_args
    body = kwargs["json"]
    assert body["user_profile"]["email"] == "u@e.com"
    assert body["user_profile"]["username"] == "jdoe"
    assert body["user_profile"]["phone_number"] == "+1234567890"
    assert body["user_profile"]["given_name"] == "Jane"
    assert body["user_profile"]["family_name"] == "Doe"
    assert body["user_profile"]["nickname"] == "jd"
    assert body["user_profile"]["picture"] == "https://example.com/pic.jpg"
    assert "user_metadata" not in body["user_profile"]
    assert body["user_metadata"] == {"role": "admin"}
    assert body["organization"] == "org_123"


@pytest.mark.asyncio
async def test_passkey_signup_challenge_minimal_body(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = MagicMock(return_value=_PASSKEY_SIGNUP_CHALLENGE_RESPONSE)
    mock_post.return_value = mock_response

    await client.passkey_signup_challenge()

    args, kwargs = mock_post.call_args
    body = kwargs["json"]
    assert body == {"client_id": "test_client_id", "client_secret": "test_client_secret"}
    assert "user_profile" not in body
    assert "user_metadata" not in body
    assert "realm" not in body
    assert "organization" not in body


@pytest.mark.asyncio
async def test_passkey_signup_challenge_user_metadata_root_level(mocker):
    """user_metadata must be sent at root level, not nested inside user_profile."""
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = MagicMock(return_value=_PASSKEY_SIGNUP_CHALLENGE_RESPONSE)
    mock_post.return_value = mock_response

    await client.passkey_signup_challenge(
        user_metadata={"preferred_language": "en"},
    )

    args, kwargs = mock_post.call_args
    body = kwargs["json"]
    assert body["user_metadata"] == {"preferred_language": "en"}
    assert "user_profile" not in body


@pytest.mark.asyncio
async def test_passkey_signup_challenge_api_error(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 403
    mock_response.json = MagicMock(return_value={
        "error": "access_denied",
        "error_description": "Passkey not enabled",
    })
    mock_post.return_value = mock_response

    with pytest.raises(PasskeyError) as exc:
        await client.passkey_signup_challenge(
            user_profile=PasskeyUserProfile(email="test@example.com")
        )
    assert "access_denied" in str(exc.value) or "Passkey not enabled" in str(exc.value)


@pytest.mark.asyncio
async def test_passkey_signup_challenge_non_json_error(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 502
    mock_response.json = MagicMock(side_effect=json.JSONDecodeError("bad", "", 0))
    mock_post.return_value = mock_response

    with pytest.raises(PasskeyError) as exc:
        await client.passkey_signup_challenge()
    assert "502" in str(exc.value) or "passkey_challenge_error" in str(exc.value)


@pytest.mark.asyncio
async def test_passkey_signup_challenge_network_error(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_post.side_effect = Exception("Connection refused")

    with pytest.raises(PasskeyError) as exc:
        await client.passkey_signup_challenge()
    assert "Passkey signup challenge failed" in str(exc.value)


@pytest.mark.asyncio
async def test_passkey_login_challenge_success(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = MagicMock(return_value=_PASSKEY_LOGIN_CHALLENGE_RESPONSE)
    mock_post.return_value = mock_response

    result = await client.passkey_login_challenge(
        connection="Username-Password-Authentication",
        organization="org_abc",
    )

    assert isinstance(result, PasskeyLoginChallengeResponse)
    assert result.auth_session == "session_login_xyz"
    assert result.authn_params_public_key.challenge == "bG9naW4tY2hhbGxlbmdl"
    assert result.authn_params_public_key.rp_id == "auth0.local"
    assert result.authn_params_public_key.user_verification == "preferred"

    args, kwargs = mock_post.call_args
    body = kwargs["json"]
    assert body["client_id"] == "test_client_id"
    assert body["realm"] == "Username-Password-Authentication"
    assert body["organization"] == "org_abc"
    assert "username" not in body


@pytest.mark.asyncio
async def test_passkey_login_challenge_minimal_body(mocker):
    """No optional fields sent when called with no arguments."""
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = MagicMock(return_value=_PASSKEY_LOGIN_CHALLENGE_RESPONSE)
    mock_post.return_value = mock_response

    await client.passkey_login_challenge()

    args, kwargs = mock_post.call_args
    body = kwargs["json"]
    assert body == {"client_id": "test_client_id", "client_secret": "test_client_secret"}
    assert "username" not in body
    assert "realm" not in body
    assert "organization" not in body


@pytest.mark.asyncio
async def test_passkey_login_challenge_with_username(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = MagicMock(return_value=_PASSKEY_LOGIN_CHALLENGE_RESPONSE)
    mock_post.return_value = mock_response

    await client.passkey_login_challenge(username="jane@example.com")

    args, kwargs = mock_post.call_args
    body = kwargs["json"]
    assert body["username"] == "jane@example.com"


@pytest.mark.asyncio
async def test_passkey_login_challenge_api_error(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 400
    mock_response.json = MagicMock(return_value={
        "error": "invalid_request",
        "error_description": "Missing client_id",
    })
    mock_post.return_value = mock_response

    with pytest.raises(PasskeyError):
        await client.passkey_login_challenge()


@pytest.mark.asyncio
async def test_passkey_login_challenge_network_error(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_post.side_effect = Exception("timeout")

    with pytest.raises(PasskeyError):
        await client.passkey_login_challenge()


@pytest.mark.asyncio
async def test_signin_with_passkey_success(mocker):
    state_store = AsyncMock()
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=state_store,
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/oauth/token", "issuer": "https://auth0.local/"},
    )
    mocker.patch.object(client, "_get_jwks_cached", return_value={})
    mocker.patch.object(client, "_verify_and_decode_jwt", return_value={
        "sub": "auth0|user123", "name": "Jane", "iss": "https://auth0.local/", "sid": "sid_abc",
        "org_id": "org_abc",
    })
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = MagicMock(return_value=_PASSKEY_TOKEN_RESPONSE)
    mock_post.return_value = mock_response
    authn_response = _make_passkey_authn_response()

    result = await client.signin_with_passkey(
        auth_session="session_xyz",
        authn_response=authn_response,
        scope="openid profile",
        audience="https://api.example.com",
        connection="Username-Password-Authentication",
        organization="org_abc",
    )

    assert isinstance(result, PasskeyLoginResult)
    assert "token_sets" in result.state_data
    assert result.state_data["token_sets"][0]["access_token"] == "at_passkey_123"
    assert result.state_data["token_sets"][0]["audience"] == "https://api.example.com"

    # Session must be persisted
    state_store.set.assert_awaited_once()

    mock_post.assert_awaited_once()
    args, kwargs = mock_post.call_args
    body = kwargs["json"]
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
async def test_signin_with_passkey_uses_json_content_type(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/oauth/token", "issuer": "https://auth0.local/"},
    )
    mocker.patch.object(client, "_get_jwks_cached", return_value={})
    mocker.patch.object(client, "_verify_and_decode_jwt", return_value={
        "sub": "auth0|user123", "iss": "https://auth0.local/"
    })
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = MagicMock(return_value=_PASSKEY_TOKEN_RESPONSE)
    mock_post.return_value = mock_response

    await client.signin_with_passkey(
        auth_session="s",
        authn_response=_make_passkey_authn_response(),
    )

    args, kwargs = mock_post.call_args
    assert "json" in kwargs
    assert "data" not in kwargs


@pytest.mark.asyncio
@pytest.mark.parametrize("auth_session", [None, ""])
async def test_signin_with_passkey_missing_auth_session(auth_session):
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    with pytest.raises(MissingRequiredArgumentError):
        await client.signin_with_passkey(
            auth_session=auth_session,
            authn_response=_make_passkey_authn_response(),
        )


@pytest.mark.asyncio
async def test_signin_with_passkey_missing_authn_response():
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    with pytest.raises(MissingRequiredArgumentError):
        await client.signin_with_passkey(
            auth_session="session_abc",
            authn_response=None,
        )


@pytest.mark.asyncio
async def test_signin_with_passkey_api_error(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/oauth/token"},
    )
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 401
    mock_response.json = MagicMock(return_value={
        "error": "invalid_grant",
        "error_description": "Invalid auth_session",
    })
    mock_post.return_value = mock_response

    with pytest.raises(PasskeyError) as exc:
        await client.signin_with_passkey(
            auth_session="expired_session",
            authn_response=_make_passkey_authn_response(),
        )
    assert "invalid_grant" in str(exc.value) or "Invalid auth_session" in str(exc.value)


@pytest.mark.asyncio
async def test_signin_with_passkey_missing_token_endpoint(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    mocker.patch.object(client, "_get_oidc_metadata_cached", return_value={})

    with pytest.raises(PasskeyError) as exc:
        await client.signin_with_passkey(
            auth_session="session",
            authn_response=_make_passkey_authn_response(),
        )
    assert "token endpoint" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_signin_with_passkey_network_error(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/oauth/token"},
    )
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_post.side_effect = Exception("Connection reset")

    with pytest.raises(PasskeyError):
        await client.signin_with_passkey(
            auth_session="session",
            authn_response=_make_passkey_authn_response(),
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
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/oauth/token", "issuer": "https://auth0.local/"},
    )
    mocker.patch.object(client, "_get_jwks_cached", return_value={})
    mocker.patch.object(client, "_verify_and_decode_jwt", return_value={
        "sub": "auth0|user123", "iss": "https://auth0.local/"
    })
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = MagicMock(return_value=_PASSKEY_TOKEN_RESPONSE)
    mock_post.return_value = mock_response

    authn_resp = PasskeyAuthResponse(
        id="cred",
        raw_id="cmF3",
        type="public-key",
        response={"clientDataJSON": "abc", "authenticatorData": "def", "signature": "ghi"},
    )
    await client.signin_with_passkey(auth_session="session", authn_response=authn_resp)

    args, kwargs = mock_post.call_args
    body = kwargs["json"]
    assert "client_secret" not in body
    assert body["client_id"] == "public_client"


def test_passkey_signup_challenge_repr_redacts_auth_session():
    resp = PasskeySignupChallengeResponse.model_validate(_PASSKEY_SIGNUP_CHALLENGE_RESPONSE)
    repr_str = repr(resp)
    assert "session_abc123" not in repr_str
    assert "[REDACTED]" in repr_str


def test_passkey_login_challenge_repr_redacts_auth_session():
    resp = PasskeyLoginChallengeResponse.model_validate(_PASSKEY_LOGIN_CHALLENGE_RESPONSE)
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


@pytest.mark.asyncio
async def test_signin_with_passkey_preserves_server_expires_at(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/oauth/token", "issuer": "https://auth0.local/"},
    )
    mocker.patch.object(client, "_get_jwks_cached", return_value={})
    mocker.patch.object(client, "_verify_and_decode_jwt", return_value={
        "sub": "auth0|user123", "iss": "https://auth0.local/"
    })
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = MagicMock(return_value={
        "access_token": "at_123",
        "token_type": "Bearer",
        "expires_in": 3600,
        "expires_at": 9999999999,
    })
    mock_post.return_value = mock_response

    result = await client.signin_with_passkey(
        auth_session="session",
        authn_response=_make_passkey_authn_response(),
    )
    assert result.state_data["token_sets"][0]["expires_at"] == 9999999999


@pytest.mark.asyncio
async def test_signin_with_passkey_missing_expires_at_calculates(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/oauth/token", "issuer": "https://auth0.local/"},
    )
    mocker.patch.object(client, "_get_jwks_cached", return_value={})
    mocker.patch.object(client, "_verify_and_decode_jwt", return_value={
        "sub": "auth0|user123", "iss": "https://auth0.local/"
    })
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = MagicMock(return_value={
        "access_token": "at_123",
        "token_type": "Bearer",
        "expires_in": 60,
    })
    mock_post.return_value = mock_response

    result = await client.signin_with_passkey(
        auth_session="session",
        authn_response=_make_passkey_authn_response(),
    )
    assert abs(result.state_data["token_sets"][0]["expires_at"] - (int(time.time()) + 60)) <= 2


@pytest.mark.asyncio
async def test_signin_with_passkey_dpop_attaches_proof_header(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/oauth/token", "issuer": "https://auth0.local/"},
    )
    mocker.patch.object(client, "_get_jwks_cached", return_value={})
    mocker.patch.object(client, "_verify_and_decode_jwt", return_value={
        "sub": "auth0|user123", "iss": "https://auth0.local/"
    })
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = MagicMock(return_value=_PASSKEY_TOKEN_RESPONSE_DPOP)
    mock_post.return_value = mock_response

    dpop_key = jwk.JWK.generate(kty="EC", crv="P-256")
    await client.signin_with_passkey(
        auth_session="session_xyz",
        authn_response=_make_passkey_authn_response(),
        dpop_key=dpop_key,
    )

    args, kwargs = mock_post.call_args
    assert "DPoP" in kwargs["headers"]

    # Decode proof and assert no ath claim (token endpoint proof — RFC 9449 §4.2)
    proof = kwargs["headers"]["DPoP"]
    payload_b64 = proof.split(".")[1]
    padding = 4 - len(payload_b64) % 4
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * padding))
    assert "ath" not in payload
    assert "jti" in payload
    assert payload["htm"] == "POST"
    assert payload["htu"] == "https://auth0.local/oauth/token"


@pytest.mark.asyncio
async def test_signin_with_passkey_dpop_nonce_retry(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/oauth/token", "issuer": "https://auth0.local/"},
    )
    mocker.patch.object(client, "_get_jwks_cached", return_value={})
    mocker.patch.object(client, "_verify_and_decode_jwt", return_value={
        "sub": "auth0|user123", "iss": "https://auth0.local/"
    })
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)

    # RFC 9449 §8.1 — the token endpoint signals a required nonce with HTTP 400.
    nonce_response = AsyncMock()
    nonce_response.status_code = 400
    nonce_response.headers = {"DPoP-Nonce": "server-nonce-abc"}
    nonce_response.json = MagicMock(return_value={"error": "use_dpop_nonce"})

    success_response = AsyncMock()
    success_response.status_code = 200
    success_response.json = MagicMock(return_value=_PASSKEY_TOKEN_RESPONSE_DPOP)

    mock_post.side_effect = [nonce_response, success_response]

    dpop_key = jwk.JWK.generate(kty="EC", crv="P-256")
    result = await client.signin_with_passkey(
        auth_session="session_xyz",
        authn_response=_make_passkey_authn_response(),
        dpop_key=dpop_key,
    )

    assert mock_post.await_count == 2
    assert result.state_data["token_sets"][0]["access_token"] == "at_passkey_dpop_123"

    # Second call must include the nonce in the DPoP proof
    second_call_kwargs = mock_post.call_args_list[1][1]
    proof = second_call_kwargs["headers"]["DPoP"]
    payload_b64 = proof.split(".")[1]
    padding = 4 - len(payload_b64) % 4
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * padding))
    assert payload["nonce"] == "server-nonce-abc"


@pytest.mark.asyncio
async def test_signin_with_passkey_dpop_nonce_retry_on_401(mocker):
    """Token endpoint nonce retry must also hold when the server returns 401 + DPoP-Nonce."""
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/oauth/token", "issuer": "https://auth0.local/"},
    )
    mocker.patch.object(client, "_get_jwks_cached", return_value={})
    mocker.patch.object(client, "_verify_and_decode_jwt", return_value={
        "sub": "auth0|user123", "iss": "https://auth0.local/"
    })
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)

    nonce_response = AsyncMock()
    nonce_response.status_code = 401
    nonce_response.headers = {"DPoP-Nonce": "server-nonce-401"}
    nonce_response.json = MagicMock(return_value={"error": "use_dpop_nonce"})

    success_response = AsyncMock()
    success_response.status_code = 200
    success_response.json = MagicMock(return_value=_PASSKEY_TOKEN_RESPONSE_DPOP)

    mock_post.side_effect = [nonce_response, success_response]

    dpop_key = jwk.JWK.generate(kty="EC", crv="P-256")
    result = await client.signin_with_passkey(
        auth_session="session_xyz",
        authn_response=_make_passkey_authn_response(),
        dpop_key=dpop_key,
    )

    assert mock_post.await_count == 2
    assert result.state_data["token_sets"][0]["access_token"] == "at_passkey_dpop_123"
    second_call_kwargs = mock_post.call_args_list[1][1]
    proof = second_call_kwargs["headers"]["DPoP"]
    payload_b64 = proof.split(".")[1]
    padding = 4 - len(payload_b64) % 4
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * padding))
    assert payload["nonce"] == "server-nonce-401"


@pytest.mark.asyncio
async def test_signin_with_passkey_dpop_rejects_bearer_downgrade(mocker):
    """Server returning token_type=Bearer when DPoP was requested must raise PasskeyError."""

    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/oauth/token", "issuer": "https://auth0.local/"},
    )
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = MagicMock(return_value=_PASSKEY_TOKEN_RESPONSE)
    mock_post.return_value = mock_response

    dpop_key = jwk.JWK.generate(kty="EC", crv="P-256")
    with pytest.raises(PasskeyError) as exc:
        await client.signin_with_passkey(
            auth_session="session_xyz",
            authn_response=_make_passkey_authn_response(),
            dpop_key=dpop_key,
        )
    assert "DPoP" in str(exc.value) or "token_type" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_signin_with_passkey_missing_issuer_in_metadata(mocker):
    """Missing 'issuer' in OIDC metadata must raise IssuerValidationError, not silently pass."""
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/oauth/token"},
    )
    mocker.patch.object(client, "_get_jwks_cached", return_value={})
    mocker.patch.object(client, "_verify_and_decode_jwt", return_value={
        "sub": "auth0|user123", "iss": "https://auth0.local/"
    })
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = MagicMock(return_value=_PASSKEY_TOKEN_RESPONSE)
    mock_post.return_value = mock_response

    with pytest.raises(Exception) as exc:
        await client.signin_with_passkey(
            auth_session="session_xyz",
            authn_response=_make_passkey_authn_response(),
        )
    assert "issuer" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_signin_with_passkey_without_dpop_no_dpop_header(mocker):
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/oauth/token", "issuer": "https://auth0.local/"},
    )
    mocker.patch.object(client, "_get_jwks_cached", return_value={})
    mocker.patch.object(client, "_verify_and_decode_jwt", return_value={
        "sub": "auth0|user123", "iss": "https://auth0.local/"
    })
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = MagicMock(return_value=_PASSKEY_TOKEN_RESPONSE)
    mock_post.return_value = mock_response

    await client.signin_with_passkey(
        auth_session="session_xyz",
        authn_response=_make_passkey_authn_response(),
    )

    args, kwargs = mock_post.call_args
    assert "DPoP" not in kwargs.get("headers", {})


@pytest.mark.asyncio
async def test_signin_with_passkey_creates_session_in_state_store(mocker):
    """signin_with_passkey must persist a session — consistent with complete_interactive_login."""
    state_store = AsyncMock()
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=state_store,
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/oauth/token", "issuer": "https://auth0.local/"},
    )
    mocker.patch.object(client, "_get_jwks_cached", return_value={})
    mocker.patch.object(client, "_verify_and_decode_jwt", return_value={
        "sub": "auth0|user123",
        "name": "Jane Doe",
        "email": "jane@example.com",
        "iss": "https://auth0.local/",
        "sid": "session_sid_abc",
    })
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = MagicMock(return_value=_PASSKEY_TOKEN_RESPONSE)
    mock_post.return_value = mock_response

    result = await client.signin_with_passkey(
        auth_session="session_xyz",
        authn_response=_make_passkey_authn_response(),
    )

    # State store must be called exactly once
    state_store.set.assert_awaited_once()

    # Result must be PasskeyLoginResult, not bare tokens
    assert isinstance(result, PasskeyLoginResult)

    # State data must contain user, token_sets, domain, internal
    sd = result.state_data
    assert sd["user"]["sub"] == "auth0|user123"
    assert sd["user"]["name"] == "Jane Doe"
    assert sd["token_sets"][0]["access_token"] == "at_passkey_123"
    assert sd["id_token"] == "eyJ.test.jwt"
    assert sd["refresh_token"] is None
    assert sd["domain"] == "auth0.local"
    assert sd["internal"]["sid"] == "session_sid_abc"
    assert "created_at" in sd["internal"]


@pytest.mark.asyncio
async def test_signin_with_passkey_session_without_id_token(mocker):
    """When no id_token is returned, session is still created with user=None."""
    state_store = AsyncMock()
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=state_store,
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/oauth/token", "issuer": "https://auth0.local/"},
    )
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = MagicMock(return_value={
        "access_token": "at_no_id_token",
        "token_type": "Bearer",
        "expires_in": 3600,
    })
    mock_post.return_value = mock_response

    result = await client.signin_with_passkey(
        auth_session="session_xyz",
        authn_response=_make_passkey_authn_response(),
    )

    assert isinstance(result, PasskeyLoginResult)
    state_store.set.assert_awaited_once()
    assert result.state_data["user"] is None
    assert result.state_data["token_sets"][0]["access_token"] == "at_no_id_token"


@pytest.mark.asyncio
async def test_signin_with_passkey_mfa_required_raises_mfa_required_error(mocker):
    """Server returns 403 mfa_required — SDK raises MfaRequiredError with encrypted token."""
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/oauth/token"},
    )
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 403
    mock_response.json = MagicMock(return_value={
        "error": "mfa_required",
        "error_description": "MFA required",
        "mfa_token": "raw_mfa_token_xyz",
    })
    mock_post.return_value = mock_response

    with pytest.raises(MfaRequiredError) as exc:
        await client.signin_with_passkey(
            auth_session="session_abc",
            authn_response=_make_passkey_authn_response(),
        )
    assert exc.value.mfa_token is not None
    assert exc.value.mfa_token != "raw_mfa_token_xyz"


@pytest.mark.asyncio
async def test_signin_with_passkey_mfa_required_with_requirements(mocker):
    """mfa_required response including mfa_requirements is propagated correctly."""
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/oauth/token"},
    )
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 403
    mock_response.json = MagicMock(return_value={
        "error": "mfa_required",
        "error_description": "MFA required",
        "mfa_token": "raw_mfa_token_xyz",
        "mfa_requirements": {"challengeTypes": ["oob"], "mfaToken": "raw_mfa_token_xyz"},
    })
    mock_post.return_value = mock_response

    with pytest.raises(MfaRequiredError) as exc:
        await client.signin_with_passkey(
            auth_session="session_abc",
            authn_response=_make_passkey_authn_response(),
        )
    assert exc.value.mfa_token is not None
    assert exc.value.mfa_requirements is not None


@pytest.mark.asyncio
async def test_signin_with_passkey_mfa_required_without_mfa_token_falls_through(mocker):
    """mfa_required response missing mfa_token raises PasskeyError (server misconfiguration)."""
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/oauth/token"},
    )
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 403
    mock_response.json = MagicMock(return_value={
        "error": "mfa_required",
        "error_description": "MFA required",
    })
    mock_post.return_value = mock_response

    with pytest.raises(PasskeyError) as exc:
        await client.signin_with_passkey(
            auth_session="session_abc",
            authn_response=_make_passkey_authn_response(),
        )
    assert exc.value.code == "mfa_required"


@pytest.mark.asyncio
async def test_signin_with_passkey_mfa_required_stores_pending_mfa(mocker):
    """When signin_with_passkey raises MfaRequiredError, the encrypted token is stored in the state store."""
    mock_store = AsyncMock()
    mock_store.get = AsyncMock(return_value=None)
    mock_store.set = AsyncMock()
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=mock_store,
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/oauth/token"},
    )
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 403
    mock_response.json = MagicMock(return_value={
        "error": "mfa_required",
        "error_description": "MFA required",
        "mfa_token": "raw_mfa_token_xyz",
    })
    mock_post.return_value = mock_response

    with pytest.raises(MfaRequiredError) as exc:
        await client.signin_with_passkey(
            auth_session="session_abc",
            authn_response=_make_passkey_authn_response(),
        )

    mock_store.set.assert_called_once()
    store_key, store_payload = mock_store.set.call_args[0][:2]
    assert store_key == "_a0_mfa_pending"
    assert store_payload["mfa_token"] == exc.value.mfa_token


def test_dpop_auth_nonce_retry_body_identical():
    """POST body bytes must be identical on initial send and nonce retry."""
    key = jwk.JWK.generate(kty="EC", crv="P-256")
    auth = DPoPAuth(token="test_access_token", key=key)
    body = b'{"key": "value", "nested": {"a": 1}}'
    request = httpx.Request("POST", "https://example.com/resource", content=body)

    flow = auth.auth_flow(request)
    first_request = next(flow)
    assert first_request.content == body

    nonce_response = httpx.Response(
        status_code=401,
        headers={"DPoP-Nonce": "server-nonce-abc"},
        request=first_request,
    )
    retried_request = flow.send(nonce_response)
    assert retried_request.content == body


@pytest.mark.asyncio
async def test_passkey_signup_challenge_uses_client_default_organization(mocker):
    """When organization is not passed, self._organization is used."""
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
        organization="org_default",
    )
    mocker.patch.object(client, "_resolve_current_domain", return_value="auth0.local")
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = MagicMock(return_value=_PASSKEY_SIGNUP_CHALLENGE_RESPONSE)
    mock_post.return_value = mock_response

    await client.passkey_signup_challenge()

    _, kwargs = mock_post.call_args
    assert kwargs["json"]["organization"] == "org_default"


@pytest.mark.asyncio
async def test_passkey_signup_challenge_call_arg_overrides_client_default_organization(mocker):
    """Call-level organization overrides self._organization."""
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
        organization="org_default",
    )
    mocker.patch.object(client, "_resolve_current_domain", return_value="auth0.local")
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = MagicMock(return_value=_PASSKEY_SIGNUP_CHALLENGE_RESPONSE)
    mock_post.return_value = mock_response

    await client.passkey_signup_challenge(organization="org_override")

    _, kwargs = mock_post.call_args
    assert kwargs["json"]["organization"] == "org_override"


@pytest.mark.asyncio
async def test_passkey_login_challenge_uses_client_default_organization(mocker):
    """When organization is not passed, self._organization is used."""
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
        organization="org_default",
    )
    mocker.patch.object(client, "_resolve_current_domain", return_value="auth0.local")
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = MagicMock(return_value=_PASSKEY_LOGIN_CHALLENGE_RESPONSE)
    mock_post.return_value = mock_response

    await client.passkey_login_challenge()

    _, kwargs = mock_post.call_args
    assert kwargs["json"]["organization"] == "org_default"


@pytest.mark.asyncio
async def test_passkey_login_challenge_call_arg_overrides_client_default_organization(mocker):
    """Call-level organization overrides self._organization."""
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret-value",
        organization="org_default",
    )
    mocker.patch.object(client, "_resolve_current_domain", return_value="auth0.local")
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = MagicMock(return_value=_PASSKEY_LOGIN_CHALLENGE_RESPONSE)
    mock_post.return_value = mock_response

    await client.passkey_login_challenge(organization="org_override")

    _, kwargs = mock_post.call_args
    assert kwargs["json"]["organization"] == "org_override"


@pytest.mark.asyncio
async def test_signin_with_passkey_uses_client_default_organization(mocker):
    """When organization is not passed, self._organization is forwarded and validated."""
    state_store = AsyncMock()
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=state_store,
        transaction_store=AsyncMock(),
        secret="test-secret-value",
        organization="org_default",
    )
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/oauth/token", "issuer": "https://auth0.local/"},
    )
    mocker.patch.object(client, "_get_jwks_cached", return_value={})
    mocker.patch.object(client, "_verify_and_decode_jwt", return_value={
        "sub": "auth0|user123", "iss": "https://auth0.local/", "org_id": "org_default",
    })
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = MagicMock(return_value=_PASSKEY_TOKEN_RESPONSE)
    mock_post.return_value = mock_response

    await client.signin_with_passkey(
        auth_session="session_xyz",
        authn_response=_make_passkey_authn_response(),
    )

    _, kwargs = mock_post.call_args
    assert kwargs["json"]["organization"] == "org_default"


@pytest.mark.asyncio
async def test_signin_with_passkey_call_arg_overrides_client_default_organization(mocker):
    """Call-level organization overrides self._organization."""
    state_store = AsyncMock()
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=state_store,
        transaction_store=AsyncMock(),
        secret="test-secret-value",
        organization="org_default",
    )
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/oauth/token", "issuer": "https://auth0.local/"},
    )
    mocker.patch.object(client, "_get_jwks_cached", return_value={})
    mocker.patch.object(client, "_verify_and_decode_jwt", return_value={
        "sub": "auth0|user123", "iss": "https://auth0.local/", "org_id": "org_override",
    })
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = MagicMock(return_value=_PASSKEY_TOKEN_RESPONSE)
    mock_post.return_value = mock_response

    await client.signin_with_passkey(
        auth_session="session_xyz",
        authn_response=_make_passkey_authn_response(),
        organization="org_override",
    )

    _, kwargs = mock_post.call_args
    assert kwargs["json"]["organization"] == "org_override"


@pytest.mark.asyncio
async def test_signin_with_passkey_org_id_mismatch_raises_and_no_session_stored(mocker):
    """org_id in ID token not matching raises OrganizationTokenValidationError; session not stored."""
    state_store = AsyncMock()
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=state_store,
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/oauth/token", "issuer": "https://auth0.local/"},
    )
    mocker.patch.object(client, "_get_jwks_cached", return_value={})
    mocker.patch.object(client, "_verify_and_decode_jwt", return_value={
        "sub": "auth0|user123", "iss": "https://auth0.local/", "org_id": "org_different",
    })
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = MagicMock(return_value=_PASSKEY_TOKEN_RESPONSE)
    mock_post.return_value = mock_response

    with pytest.raises(OrganizationTokenValidationError):
        await client.signin_with_passkey(
            auth_session="session_xyz",
            authn_response=_make_passkey_authn_response(),
            organization="org_expected",
        )

    state_store.set.assert_not_awaited()


@pytest.mark.asyncio
async def test_signin_with_passkey_org_name_mismatch_raises_and_no_session_stored(mocker):
    """org_name in ID token not matching raises OrganizationTokenValidationError; session not stored."""
    state_store = AsyncMock()
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=state_store,
        transaction_store=AsyncMock(),
        secret="test-secret-value",
    )
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/oauth/token", "issuer": "https://auth0.local/"},
    )
    mocker.patch.object(client, "_get_jwks_cached", return_value={})
    mocker.patch.object(client, "_verify_and_decode_jwt", return_value={
        "sub": "auth0|user123", "iss": "https://auth0.local/", "org_name": "acme",
    })
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = MagicMock(return_value=_PASSKEY_TOKEN_RESPONSE)
    mock_post.return_value = mock_response

    with pytest.raises(OrganizationTokenValidationError):
        await client.signin_with_passkey(
            auth_session="session_xyz",
            authn_response=_make_passkey_authn_response(),
            organization="different-org",
        )

    state_store.set.assert_not_awaited()


@pytest.mark.asyncio
async def test_signin_with_passkey_client_default_org_is_validated_against_id_token(mocker):
    """self._organization fallback is validated against the ID token org claims."""
    state_store = AsyncMock()
    client = ServerClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        state_store=state_store,
        transaction_store=AsyncMock(),
        secret="test-secret-value",
        organization="org_mismatch",
    )
    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"token_endpoint": "https://auth0.local/oauth/token", "issuer": "https://auth0.local/"},
    )
    mocker.patch.object(client, "_get_jwks_cached", return_value={})
    mocker.patch.object(client, "_verify_and_decode_jwt", return_value={
        "sub": "auth0|user123", "iss": "https://auth0.local/", "org_id": "org_different",
    })
    mock_post = mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = MagicMock(return_value=_PASSKEY_TOKEN_RESPONSE)
    mock_post.return_value = mock_response

    with pytest.raises(OrganizationTokenValidationError):
        await client.signin_with_passkey(
            auth_session="session_xyz",
            authn_response=_make_passkey_authn_response(),
        )

    state_store.set.assert_not_awaited()


@pytest.mark.asyncio
async def test_get_access_token_mfa_required_stores_pending_mfa(mocker):
    """When get_access_token raises MfaRequiredError, the encrypted token is stored in the state store."""
    mock_secret = "a-test-secret-with-enough-length"
    mock_store = AsyncMock()
    mock_store.get = AsyncMock(return_value={
        "refresh_token": "rt_123",
        "token_sets": [
            {"audience": "default", "access_token": "expired_at", "expires_at": 0}
        ]
    })
    mock_store.set = AsyncMock()
    mock_store.delete = AsyncMock()

    client = ServerClient(
        domain="auth0.local",
        client_id="cid",
        client_secret="csecret",
        secret=mock_secret,
        transaction_store=mock_store,
        state_store=mock_store,
    )

    encrypted_token = client._mfa_client._encrypt_mfa_token(
        raw_mfa_token="raw_mfa_token_xyz",
        audience="default",
        scope="",
    )
    mfa_err = MfaRequiredError(
        "Multifactor authentication required",
        mfa_token=encrypted_token,
    )
    mocker.patch.object(client, "get_token_by_refresh_token",
                        new_callable=AsyncMock, side_effect=mfa_err)

    with pytest.raises(MfaRequiredError):
        await client.get_access_token()

    pending_calls = [
        call for call in mock_store.set.call_args_list
        if call[0][0] == "_a0_mfa_pending"
    ]
    assert len(pending_calls) == 1
    assert pending_calls[0][0][1]["mfa_token"] == encrypted_token


@pytest.mark.asyncio
async def test_mfa_client_store_and_get_pending_mfa():
    """store_pending_mfa / get_pending_mfa roundtrip through the state store."""
    store = AsyncMock()
    store.set = AsyncMock()
    store.get = AsyncMock(return_value={"mfa_token": "enc_tok"})

    client = MfaClient(
        domain="auth0.local",
        client_id="cid",
        client_secret="csecret",
        secret="a-test-secret-with-enough-length",
        state_store=store,
    )

    await client.store_pending_mfa("enc_tok")
    store.set.assert_called_once_with(
        "_a0_mfa_pending", {"mfa_token": "enc_tok"}, options=None
    )

    result = await client.get_pending_mfa()
    assert result == "enc_tok"


# ORGANIZATIONS SUPPORT TESTS

def _make_org_client(mocker, transaction_data: TransactionData, **extra):
    """Helper: build a ServerClient with mocked stores and standard JWT mocks."""
    mock_tx_store = AsyncMock()
    mock_tx_store.get.return_value = transaction_data
    mock_state_store = AsyncMock()

    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="test_client",
        client_secret="test_secret",
        transaction_store=mock_tx_store,
        state_store=mock_state_store,
        secret="test_secret_key_32_chars_long!!",
        **extra
    )

    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={
            "issuer": "https://tenant.auth0.com/",
            "token_endpoint": "https://tenant.auth0.com/token",
            "authorization_endpoint": "https://tenant.auth0.com/authorize",
        }
    )
    mocker.patch.object(
        client,
        "_get_jwks_cached",
        return_value={"keys": [{"kty": "RSA", "kid": "test-key"}]}
    )
    async_fetch_token = AsyncMock(return_value={
        "access_token": "at123",
        "id_token": "id_token_jwt",
        "scope": "openid profile",
    })
    mocker.patch.object(client._oauth, "fetch_token", async_fetch_token)
    mocker.patch("jwt.get_unverified_header", return_value={"kid": "test-key"})
    mock_signing_key = mocker.MagicMock()
    mock_signing_key.key = "mock_pem_key"
    mocker.patch("jwt.PyJWK.from_dict", return_value=mock_signing_key)
    return client



@pytest.mark.asyncio
async def test_org_by_id_matching_claim_succeeds(mocker):
    """Token with matching org_id passes validation."""
    client = _make_org_client(
        mocker,
        TransactionData(code_verifier="cv", domain="tenant.auth0.com", organization="org_abc123"),
    )
    mocker.patch("jwt.decode", return_value={
        "sub": "u1", "iss": "https://tenant.auth0.com/",
        "aud": "test_client", "org_id": "org_abc123",
    })
    result = await client.complete_interactive_login("http://localhost/cb?code=abc&state=xyz")
    assert result["state_data"]["user"]["org_id"] == "org_abc123"



@pytest.mark.asyncio
async def test_org_by_id_missing_claim_raises(mocker):
    """Token missing org_id raises OrganizationTokenValidationError."""
    client = _make_org_client(
        mocker,
        TransactionData(code_verifier="cv", domain="tenant.auth0.com", organization="org_abc123"),
    )
    mocker.patch("jwt.decode", return_value={
        "sub": "u1", "iss": "https://tenant.auth0.com/", "aud": "test_client",
        # no org_id
    })
    with pytest.raises(OrganizationTokenValidationError) as exc:
        await client.complete_interactive_login("http://localhost/cb?code=abc&state=xyz")
    assert "org_id" in str(exc.value)
    assert "must be a string present" in str(exc.value)



@pytest.mark.asyncio
async def test_org_by_id_wrong_claim_raises(mocker):
    """Token with wrong org_id raises OrganizationTokenValidationError with mismatch detail."""
    client = _make_org_client(
        mocker,
        TransactionData(code_verifier="cv", domain="tenant.auth0.com", organization="org_abc123"),
    )
    mocker.patch("jwt.decode", return_value={
        "sub": "u1", "iss": "https://tenant.auth0.com/", "aud": "test_client",
        "org_id": "org_attacker",
    })
    with pytest.raises(OrganizationTokenValidationError) as exc:
        await client.complete_interactive_login("http://localhost/cb?code=abc&state=xyz")
    assert "mismatch" in str(exc.value)



@pytest.mark.asyncio
async def test_org_by_id_null_claim_raises(mocker):
    """Token with null org_id raises OrganizationTokenValidationError."""
    client = _make_org_client(
        mocker,
        TransactionData(code_verifier="cv", domain="tenant.auth0.com", organization="org_abc123"),
    )
    mocker.patch("jwt.decode", return_value={
        "sub": "u1", "iss": "https://tenant.auth0.com/", "aud": "test_client",
        "org_id": None,
    })
    with pytest.raises(OrganizationTokenValidationError) as exc:
        await client.complete_interactive_login("http://localhost/cb?code=abc&state=xyz")
    assert "org_id" in str(exc.value)



@pytest.mark.asyncio
async def test_org_by_name_exact_match_succeeds(mocker):
    """Token with matching org_name (exact case) passes validation."""
    client = _make_org_client(
        mocker,
        TransactionData(code_verifier="cv", domain="tenant.auth0.com", organization="acme-corp"),
    )
    mocker.patch("jwt.decode", return_value={
        "sub": "u1", "iss": "https://tenant.auth0.com/", "aud": "test_client",
        "org_name": "acme-corp",
    })
    result = await client.complete_interactive_login("http://localhost/cb?code=abc&state=xyz")
    assert result is not None



@pytest.mark.asyncio
async def test_org_by_name_case_insensitive_match_succeeds(mocker):
    """Token with org_name differing only in case passes validation."""
    client = _make_org_client(
        mocker,
        TransactionData(code_verifier="cv", domain="tenant.auth0.com", organization="ACME-CORP"),
    )
    mocker.patch("jwt.decode", return_value={
        "sub": "u1", "iss": "https://tenant.auth0.com/", "aud": "test_client",
        "org_name": "acme-corp",
    })
    result = await client.complete_interactive_login("http://localhost/cb?code=abc&state=xyz")
    assert result is not None



@pytest.mark.asyncio
async def test_org_by_name_missing_claim_raises(mocker):
    """Token missing org_name raises OrganizationTokenValidationError."""
    client = _make_org_client(
        mocker,
        TransactionData(code_verifier="cv", domain="tenant.auth0.com", organization="acme-corp"),
    )
    mocker.patch("jwt.decode", return_value={
        "sub": "u1", "iss": "https://tenant.auth0.com/", "aud": "test_client",
        # no org_name
    })
    with pytest.raises(OrganizationTokenValidationError) as exc:
        await client.complete_interactive_login("http://localhost/cb?code=abc&state=xyz")
    assert "org_name" in str(exc.value)
    assert "must be a string present" in str(exc.value)



@pytest.mark.asyncio
async def test_org_by_name_wrong_claim_raises(mocker):
    """Token with wrong org_name raises OrganizationTokenValidationError with detail."""
    client = _make_org_client(
        mocker,
        TransactionData(code_verifier="cv", domain="tenant.auth0.com", organization="acme-corp"),
    )
    mocker.patch("jwt.decode", return_value={
        "sub": "u1", "iss": "https://tenant.auth0.com/", "aud": "test_client",
        "org_name": "evil-corp",
    })
    with pytest.raises(OrganizationTokenValidationError) as exc:
        await client.complete_interactive_login("http://localhost/cb?code=abc&state=xyz")
    assert "mismatch" in str(exc.value)



@pytest.mark.asyncio
async def test_no_org_requested_token_with_org_id_passes(mocker):
    """When no org was requested, tokens carrying org_id must not be rejected."""
    client = _make_org_client(
        mocker,
        TransactionData(code_verifier="cv", domain="tenant.auth0.com"),  # no organization
    )
    mocker.patch("jwt.decode", return_value={
        "sub": "u1", "iss": "https://tenant.auth0.com/", "aud": "test_client",
        "org_id": "org_abc123", "org_name": "acme",
    })
    result = await client.complete_interactive_login("http://localhost/cb?code=abc&state=xyz")
    assert result["state_data"]["user"]["org_id"] == "org_abc123"
    assert result["state_data"]["user"]["org_name"] == "acme"



@pytest.mark.asyncio
async def test_no_org_requested_plain_token_passes(mocker):
    """When no org was requested, a token without org claims passes normally."""
    client = _make_org_client(
        mocker,
        TransactionData(code_verifier="cv", domain="tenant.auth0.com"),
    )
    mocker.patch("jwt.decode", return_value={
        "sub": "u1", "iss": "https://tenant.auth0.com/", "aud": "test_client",
    })
    result = await client.complete_interactive_login("http://localhost/cb?code=abc&state=xyz")
    assert result is not None



@pytest.mark.asyncio
async def test_invitation_and_org_forwarded_to_authorize(mocker):
    """organization and invitation appear in the authorization URL."""
    mock_tx_store = AsyncMock()
    mock_state_store = AsyncMock()
    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="test_client",
        client_secret="test_secret",
        redirect_uri="https://app.example.com/callback",
        transaction_store=mock_tx_store,
        state_store=mock_state_store,
        secret="test_secret_key_32_chars_long!!",
    )
    mocker.patch.object(client, "_get_oidc_metadata_cached", return_value={
        "issuer": "https://tenant.auth0.com/",
        "authorization_endpoint": "https://tenant.auth0.com/authorize",
    })

    url = await client.start_interactive_login(
        StartInteractiveLoginOptions(
            organization="org_abc123",
            invitation="inv_token_xyz",
        )
    )

    assert "organization=org_abc123" in url
    assert "invitation=inv_token_xyz" in url

    # Confirm transaction stores the organization
    stored = mock_tx_store.set.call_args[0][1]
    assert stored.organization == "org_abc123"


@pytest.mark.asyncio
async def test_invitation_without_org_forwarded_to_authorize(mocker):
    """invitation alone appears in the URL; no organization param."""
    mock_tx_store = AsyncMock()
    mock_state_store = AsyncMock()
    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="test_client",
        client_secret="test_secret",
        redirect_uri="https://app.example.com/callback",
        transaction_store=mock_tx_store,
        state_store=mock_state_store,
        secret="test_secret_key_32_chars_long!!",
    )
    mocker.patch.object(client, "_get_oidc_metadata_cached", return_value={
        "issuer": "https://tenant.auth0.com/",
        "authorization_endpoint": "https://tenant.auth0.com/authorize",
    })

    url = await client.start_interactive_login(
        StartInteractiveLoginOptions(
            invitation="inv_token_xyz",
        )
    )

    assert "invitation=inv_token_xyz" in url
    assert "organization=" not in url


@pytest.mark.asyncio
async def test_per_login_org_overrides_client_org(mocker):
    """Per-login organization overrides the client-level default."""
    mock_tx_store = AsyncMock()
    mock_state_store = AsyncMock()
    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="test_client",
        client_secret="test_secret",
        redirect_uri="https://app.example.com/callback",
        transaction_store=mock_tx_store,
        state_store=mock_state_store,
        secret="test_secret_key_32_chars_long!!",
        organization="org_default",
    )
    mocker.patch.object(client, "_get_oidc_metadata_cached", return_value={
        "issuer": "https://tenant.auth0.com/",
        "authorization_endpoint": "https://tenant.auth0.com/authorize",
    })

    url = await client.start_interactive_login(
        StartInteractiveLoginOptions(organization="org_override")
    )

    assert "organization=org_override" in url
    assert "org_default" not in url

    stored = mock_tx_store.set.call_args[0][1]
    assert stored.organization == "org_override"



@pytest.mark.asyncio
async def test_client_level_org_used_when_no_per_login_org(mocker):
    """Client-level organization is used when no per-login org is set."""
    mock_tx_store = AsyncMock()
    mock_state_store = AsyncMock()
    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="test_client",
        client_secret="test_secret",
        redirect_uri="https://app.example.com/callback",
        transaction_store=mock_tx_store,
        state_store=mock_state_store,
        secret="test_secret_key_32_chars_long!!",
        organization="org_default",
    )
    mocker.patch.object(client, "_get_oidc_metadata_cached", return_value={
        "issuer": "https://tenant.auth0.com/",
        "authorization_endpoint": "https://tenant.auth0.com/authorize",
    })

    url = await client.start_interactive_login(StartInteractiveLoginOptions())

    assert "organization=org_default" in url
    stored = mock_tx_store.set.call_args[0][1]
    assert stored.organization == "org_default"



@pytest.mark.asyncio
async def test_org_name_present_in_user_claims_after_org_login(mocker):
    """org_id and org_name both surface in session user claims."""
    client = _make_org_client(
        mocker,
        TransactionData(code_verifier="cv", domain="tenant.auth0.com", organization="org_abc123"),
    )
    mocker.patch("jwt.decode", return_value={
        "sub": "u1", "iss": "https://tenant.auth0.com/", "aud": "test_client",
        "org_id": "org_abc123", "org_name": "acme-corp",
    })
    result = await client.complete_interactive_login("http://localhost/cb?code=abc&state=xyz")
    user = result["state_data"]["user"]
    assert user["org_id"] == "org_abc123"
    assert user["org_name"] == "acme-corp"


# Adversarial tests

@pytest.mark.asyncio
async def test_adv_org_id_is_integer_not_string_raises(mocker):
    """org_id claim as integer (not string) raises OrganizationTokenValidationError."""
    client = _make_org_client(
        mocker,
        TransactionData(code_verifier="cv", domain="tenant.auth0.com", organization="org_abc123"),
    )
    mocker.patch("jwt.decode", return_value={
        "sub": "u1", "iss": "https://tenant.auth0.com/", "aud": "test_client",
        "org_id": 12345,
    })
    with pytest.raises(OrganizationTokenValidationError):
        await client.complete_interactive_login("http://localhost/cb?code=abc&state=xyz")


@pytest.mark.asyncio
async def test_adv_org_name_is_array_raises(mocker):
    """org_name claim as array raises OrganizationTokenValidationError."""
    client = _make_org_client(
        mocker,
        TransactionData(code_verifier="cv", domain="tenant.auth0.com", organization="acme"),
    )
    mocker.patch("jwt.decode", return_value={
        "sub": "u1", "iss": "https://tenant.auth0.com/", "aud": "test_client",
        "org_name": ["acme", "other"],
    })
    with pytest.raises(OrganizationTokenValidationError):
        await client.complete_interactive_login("http://localhost/cb?code=abc&state=xyz")


@pytest.mark.asyncio
async def test_adv_empty_string_org_id_raises(mocker):
    """Empty string org_id claim raises OrganizationTokenValidationError (mismatch)."""
    client = _make_org_client(
        mocker,
        TransactionData(code_verifier="cv", domain="tenant.auth0.com", organization="org_abc123"),
    )
    mocker.patch("jwt.decode", return_value={
        "sub": "u1", "iss": "https://tenant.auth0.com/", "aud": "test_client",
        "org_id": "",
    })
    with pytest.raises(OrganizationTokenValidationError) as exc:
        await client.complete_interactive_login("http://localhost/cb?code=abc&state=xyz")
    assert "mismatch" in str(exc.value)


@pytest.mark.asyncio
async def test_adv_org_in_authorization_params_is_forwarded(mocker):
    """organization passed via authorization_params is forwarded to /authorize."""
    mock_tx_store = AsyncMock()
    mock_state_store = AsyncMock()
    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="test_client",
        client_secret="test_secret",
        redirect_uri="https://app.example.com/callback",
        transaction_store=mock_tx_store,
        state_store=mock_state_store,
        secret="test_secret_key_32_chars_long!!",
    )
    mocker.patch.object(client, "_get_oidc_metadata_cached", return_value={
        "issuer": "https://tenant.auth0.com/",
        "authorization_endpoint": "https://tenant.auth0.com/authorize",
    })

    url = await client.start_interactive_login(
        StartInteractiveLoginOptions(
            authorization_params={"organization": "org_via_dict"},
        )
    )

    parsed = parse_qs(urlparse(url).query)
    assert parsed["organization"] == ["org_via_dict"]


@pytest.mark.asyncio
async def test_adv_invitation_in_authorization_params_is_forwarded(mocker):
    """invitation passed via authorization_params is forwarded to /authorize."""
    mock_tx_store = AsyncMock()
    mock_state_store = AsyncMock()
    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="test_client",
        client_secret="test_secret",
        redirect_uri="https://app.example.com/callback",
        transaction_store=mock_tx_store,
        state_store=mock_state_store,
        secret="test_secret_key_32_chars_long!!",
    )
    mocker.patch.object(client, "_get_oidc_metadata_cached", return_value={
        "issuer": "https://tenant.auth0.com/",
        "authorization_endpoint": "https://tenant.auth0.com/authorize",
    })

    url = await client.start_interactive_login(
        StartInteractiveLoginOptions(
            authorization_params={"invitation": "inv_via_dict"},
        )
    )

    parsed = parse_qs(urlparse(url).query)
    assert parsed["invitation"] == ["inv_via_dict"]


@pytest.mark.asyncio
async def test_adv_typed_invitation_wins_over_dict(mocker):
    """Typed invitation field wins when both typed and dict values are present."""
    mock_tx_store = AsyncMock()
    mock_state_store = AsyncMock()
    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="test_client",
        client_secret="test_secret",
        redirect_uri="https://app.example.com/callback",
        transaction_store=mock_tx_store,
        state_store=mock_state_store,
        secret="test_secret_key_32_chars_long!!",
    )
    mocker.patch.object(client, "_get_oidc_metadata_cached", return_value={
        "issuer": "https://tenant.auth0.com/",
        "authorization_endpoint": "https://tenant.auth0.com/authorize",
    })

    url = await client.start_interactive_login(
        StartInteractiveLoginOptions(
            invitation="inv_typed",
            authorization_params={"invitation": "inv_via_dict"},
        )
    )

    parsed = parse_qs(urlparse(url).query)
    assert parsed["invitation"] == ["inv_typed"]


@pytest.mark.asyncio
async def test_adv_typed_org_wins_over_dict_injection(mocker):
    """Typed organization field wins when both typed and dict values are present."""
    mock_tx_store = AsyncMock()
    mock_state_store = AsyncMock()
    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="test_client",
        client_secret="test_secret",
        redirect_uri="https://app.example.com/callback",
        transaction_store=mock_tx_store,
        state_store=mock_state_store,
        secret="test_secret_key_32_chars_long!!",
    )
    mocker.patch.object(client, "_get_oidc_metadata_cached", return_value={
        "issuer": "https://tenant.auth0.com/",
        "authorization_endpoint": "https://tenant.auth0.com/authorize",
    })

    url = await client.start_interactive_login(
        StartInteractiveLoginOptions(
            organization="org_legitimate",
            authorization_params={"organization": "org_attacker"},
        )
    )

    # TransactionData stores the typed value
    stored = mock_tx_store.set.call_args[0][1]
    assert stored.organization == "org_legitimate"

    # URL must contain only the typed value
    parsed = parse_qs(urlparse(url).query)
    org_values = parsed.get("organization", [])
    assert org_values == ["org_legitimate"]


@pytest.mark.asyncio
async def test_adv_unicode_nfc_nfd_org_name_matches(mocker):
    """ADV-005: NFC and NFD representations of the same org name are treated as equal."""
    # "café" NFC: é is U+00E9 (single precomposed codepoint)
    # "café" NFD: é is U+0065 U+0301 (base letter + combining accent)
    nfc_name = unicodedata.normalize("NFC", "café")
    nfd_name = unicodedata.normalize("NFD", "café")
    assert nfc_name != nfd_name, "precondition: NFC and NFD byte sequences differ"

    client = _make_org_client(
        mocker,
        TransactionData(code_verifier="cv", domain="tenant.auth0.com", organization=nfd_name),
    )
    mocker.patch("jwt.decode", return_value={
        "sub": "u1", "iss": "https://tenant.auth0.com/", "aud": "test_client",
        "org_name": nfc_name,
    })
    result = await client.complete_interactive_login("http://localhost/cb?code=abc&state=xyz")
    assert result is not None


# Error class properties

def test_organization_token_validation_error_code():
    """OrganizationTokenValidationError has the correct code and message."""
    err = OrganizationTokenValidationError("test message")
    assert err.code == "organization_token_validation_error"
    assert err.name == "OrganizationTokenValidationError"
    assert str(err) == "test message"



@pytest.mark.asyncio
async def test_org_userinfo_path_matching_org_id_succeeds(mocker):
    """userinfo response with matching org_id passes validation."""
    mock_tx_store = AsyncMock()
    mock_tx_store.get.return_value = TransactionData(
        code_verifier="cv", domain="tenant.auth0.com", organization="org_abc123"
    )
    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = None
    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="test_client",
        client_secret="test_secret",
        secret="test_secret_key_32_chars_long!!",
        transaction_store=mock_tx_store,
        state_store=mock_state_store,
    )
    mocker.patch.object(
        client, "_get_oidc_metadata_cached",
        return_value={
            "issuer": "https://tenant.auth0.com/",
            "token_endpoint": "https://tenant.auth0.com/token",
        }
    )
    # Token response returns userinfo (no id_token)
    mocker.patch.object(client._oauth, "fetch_token", AsyncMock(return_value={
        "access_token": "at123",
        "userinfo": {"sub": "u1", "org_id": "org_abc123"},
    }))
    result = await client.complete_interactive_login("http://localhost/cb?code=abc&state=xyz")
    assert result["state_data"]["user"]["org_id"] == "org_abc123"


@pytest.mark.asyncio
async def test_org_userinfo_path_wrong_org_id_raises(mocker):
    """userinfo response with wrong org_id raises OrganizationTokenValidationError."""
    mock_tx_store = AsyncMock()
    mock_tx_store.get.return_value = TransactionData(
        code_verifier="cv", domain="tenant.auth0.com", organization="org_abc123"
    )
    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = None
    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="test_client",
        client_secret="test_secret",
        secret="test_secret_key_32_chars_long!!",
        transaction_store=mock_tx_store,
        state_store=mock_state_store,
    )
    mocker.patch.object(
        client, "_get_oidc_metadata_cached",
        return_value={
            "issuer": "https://tenant.auth0.com/",
            "token_endpoint": "https://tenant.auth0.com/token",
        }
    )
    mocker.patch.object(client._oauth, "fetch_token", AsyncMock(return_value={
        "access_token": "at123",
        "userinfo": {"sub": "u1", "org_id": "org_different"},
    }))
    with pytest.raises(OrganizationTokenValidationError) as exc:
        await client.complete_interactive_login("http://localhost/cb?code=abc&state=xyz")
    assert "mismatch" in str(exc.value)


@pytest.mark.asyncio
async def test_org_userinfo_path_missing_org_id_raises(mocker):
    """userinfo response missing org_id raises OrganizationTokenValidationError."""
    mock_tx_store = AsyncMock()
    mock_tx_store.get.return_value = TransactionData(
        code_verifier="cv", domain="tenant.auth0.com", organization="org_abc123"
    )
    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = None
    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="test_client",
        client_secret="test_secret",
        secret="test_secret_key_32_chars_long!!",
        transaction_store=mock_tx_store,
        state_store=mock_state_store,
    )
    mocker.patch.object(
        client, "_get_oidc_metadata_cached",
        return_value={
            "issuer": "https://tenant.auth0.com/",
            "token_endpoint": "https://tenant.auth0.com/token",
        }
    )
    mocker.patch.object(client._oauth, "fetch_token", AsyncMock(return_value={
        "access_token": "at123",
        "userinfo": {"sub": "u1"},  # no org_id
    }))
    with pytest.raises(OrganizationTokenValidationError) as exc:
        await client.complete_interactive_login("http://localhost/cb?code=abc&state=xyz")
    assert "must be a string present" in str(exc.value)



@pytest.mark.asyncio
async def test_org_requested_no_userinfo_no_id_token_fails_closed(mocker):
    """org was requested but token response has neither user_info nor id_token — fails closed."""
    mock_tx_store = AsyncMock()
    mock_tx_store.get.return_value = TransactionData(
        code_verifier="cv", domain="tenant.auth0.com", organization="org_abc123"
    )
    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = None
    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="test_client",
        client_secret="test_secret",
        secret="test_secret_key_32_chars_long!!",
        transaction_store=mock_tx_store,
        state_store=mock_state_store,
    )
    mocker.patch.object(
        client, "_get_oidc_metadata_cached",
        return_value={
            "issuer": "https://tenant.auth0.com/",
            "token_endpoint": "https://tenant.auth0.com/token",
        }
    )
    mocker.patch.object(client._oauth, "fetch_token", AsyncMock(return_value={
        "access_token": "at123",
        # neither user_info nor id_token
    }))
    with pytest.raises(OrganizationTokenValidationError) as exc:
        await client.complete_interactive_login("http://localhost/cb?code=abc&state=xyz")
    assert "neither" in str(exc.value)



@pytest.mark.asyncio
async def test_org_userinfo_non_dict_raises_organization_error(mocker):
    """Non-dict truthy userinfo raises OrganizationTokenValidationError when org is requested."""
    mock_tx_store = AsyncMock()
    mock_tx_store.get.return_value = TransactionData(
        code_verifier="cv", domain="tenant.auth0.com", organization="org_abc123"
    )
    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = None
    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="test_client",
        client_secret="test_secret",
        secret="test_secret_key_32_chars_long!!",
        transaction_store=mock_tx_store,
        state_store=mock_state_store,
    )
    mocker.patch.object(
        client, "_get_oidc_metadata_cached",
        return_value={
            "issuer": "https://tenant.auth0.com/",
            "token_endpoint": "https://tenant.auth0.com/token",
        }
    )
    # Return a string (truthy, but not a dict) as userinfo
    mocker.patch.object(client._oauth, "fetch_token", AsyncMock(return_value={
        "access_token": "at123",
        "userinfo": "not-a-dict",
    }))
    with pytest.raises(OrganizationTokenValidationError) as exc:
        await client.complete_interactive_login("http://localhost/cb?code=abc&state=xyz")
    assert "valid claims dictionary" in str(exc.value)


@pytest.mark.asyncio
async def test_userinfo_non_dict_no_org_raises_api_error(mocker):
    """Non-dict truthy userinfo without org requested raises ApiError (not OrganizationTokenValidationError)."""
    mock_tx_store = AsyncMock()
    mock_tx_store.get.return_value = TransactionData(
        code_verifier="cv", domain="tenant.auth0.com",
    )
    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = None
    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="test_client",
        client_secret="test_secret",
        secret="test_secret_key_32_chars_long!!",
        transaction_store=mock_tx_store,
        state_store=mock_state_store,
    )
    mocker.patch.object(
        client, "_get_oidc_metadata_cached",
        return_value={
            "issuer": "https://tenant.auth0.com/",
            "token_endpoint": "https://tenant.auth0.com/token",
        }
    )
    mocker.patch.object(client._oauth, "fetch_token", AsyncMock(return_value={
        "access_token": "at123",
        "userinfo": "not-a-dict",
    }))
    with pytest.raises(ApiError) as exc:
        await client.complete_interactive_login("http://localhost/cb?code=abc&state=xyz")
    assert exc.value.code == "invalid_response"
    assert "valid claims dictionary" in str(exc.value)


# ---------------------------------------------------------------------------
# complete_interactive_login — org errors raised as ApiError
# ---------------------------------------------------------------------------

def _make_org_callback_client(mock_tx_store, mock_state_store, org=None):
    return ServerClient(
        domain="tenant.auth0.com",
        client_id="test_client",
        client_secret="test_secret",
        secret="test_secret_key_32_chars_long!!",
        organization=org,
        transaction_store=mock_tx_store,
        state_store=mock_state_store,
    )


@pytest.mark.asyncio
async def test_callback_org_access_denied_raises_api_error():
    """access_denied from org membership check → ApiError with original code and description."""
    mock_tx_store = AsyncMock()
    mock_tx_store.get.return_value = TransactionData(
        code_verifier="cv", domain="tenant.auth0.com", organization="org_abc"
    )
    client = _make_org_callback_client(mock_tx_store, AsyncMock(), org="org_abc")
    desc = "user u1 is not part of the org_abc organization"
    url = f"http://localhost/cb?state=xyz&error=access_denied&error_description={desc}"
    with pytest.raises(ApiError) as exc:
        await client.complete_interactive_login(url)
    assert exc.value.code == "access_denied"
    assert desc in exc.value.message


@pytest.mark.asyncio
async def test_callback_org_invalid_format_raises_api_error():
    """invalid_request with bad org format → ApiError with original code and description."""
    mock_tx_store = AsyncMock()
    mock_tx_store.get.return_value = TransactionData(
        code_verifier="cv", domain="tenant.auth0.com", organization="my-org"
    )
    client = _make_org_callback_client(mock_tx_store, AsyncMock())
    desc = "authorization request parameter organization must be an organization id"
    url = f"http://localhost/cb?state=xyz&error=invalid_request&error_description={desc}"
    with pytest.raises(ApiError) as exc:
        await client.complete_interactive_login(url)
    assert exc.value.code == "invalid_request"
    assert desc in exc.value.message


@pytest.mark.asyncio
async def test_callback_invitation_error_raises_api_error():
    """Expired/invalid invitation ticket → ApiError with original code and description."""
    mock_tx_store = AsyncMock()
    mock_tx_store.get.return_value = TransactionData(
        code_verifier="cv", domain="tenant.auth0.com", organization="org_abc"
    )
    client = _make_org_callback_client(mock_tx_store, AsyncMock(), org="org_abc")
    desc = "invalid_user_invitation_ticket: ticket has already been used"
    url = f"http://localhost/cb?state=xyz&error=invalid_request&error_description={desc}"
    with pytest.raises(ApiError) as exc:
        await client.complete_interactive_login(url)
    assert exc.value.code == "invalid_request"
    assert desc in exc.value.message


@pytest.mark.asyncio
async def test_callback_error_raises_api_error():
    """Any auth error → ApiError preserving the raw error code and description."""
    mock_tx_store = AsyncMock()
    mock_tx_store.get.return_value = TransactionData(
        code_verifier="cv", domain="tenant.auth0.com",
    )
    client = _make_org_callback_client(mock_tx_store, AsyncMock())
    url = "http://localhost/cb?state=xyz&error=access_denied&error_description=User+cancelled"
    with pytest.raises(ApiError) as exc:
        await client.complete_interactive_login(url)
    assert type(exc.value) is ApiError
    assert exc.value.code == "access_denied"


# ---------------------------------------------------------------------------
# Org resolution — per-login vs client-level precedence
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_per_login_org_overrides_client_default(mocker):
    """
    A per-login org value overrides the client-level default.
    Both paths end up in TransactionData — this is the multi-org scenario regression guard.
    """
    mock_tx_store = AsyncMock()
    stored_tx = None

    async def capture_set(key, value, options=None):
        nonlocal stored_tx
        stored_tx = value

    mock_tx_store.set.side_effect = capture_set

    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="cid",
        client_secret="csec",
        secret="test_secret_key_32_chars_long!!",
        organization="org_default",
        redirect_uri="https://app.example.com/callback",
        transaction_store=mock_tx_store,
        state_store=AsyncMock(),
    )
    mocker.patch.object(client, "_get_oidc_metadata_cached", return_value={
        "issuer": "https://tenant.auth0.com/",
        "authorization_endpoint": "https://tenant.auth0.com/authorize",
    })
    mocker.patch.object(client._oauth, "create_authorization_url",
                        return_value=("https://tenant.auth0.com/authorize?state=x", "x"))

    await client.start_interactive_login(
        StartInteractiveLoginOptions(organization="org_override")
    )

    assert stored_tx.organization == "org_override"


@pytest.mark.asyncio
async def test_blank_org_raises_invalid_argument_error(mocker):
    """Whitespace-only organization value is rejected with InvalidArgumentError."""
    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="cid",
        client_secret="csec",
        secret="test_secret_key_32_chars_long!!",
        redirect_uri="https://app.example.com/callback",
        transaction_store=AsyncMock(),
        state_store=AsyncMock(),
    )
    mocker.patch.object(client, "_get_oidc_metadata_cached", return_value={
        "issuer": "https://tenant.auth0.com/",
        "authorization_endpoint": "https://tenant.auth0.com/authorize",
    })

    with pytest.raises(InvalidArgumentError) as exc:
        await client.start_interactive_login(
            StartInteractiveLoginOptions(organization="   ")
        )
    assert "organization" in exc.value.argument


@pytest.mark.asyncio
async def test_client_level_org_used_when_options_org_is_none_not_set(mocker):
    """
    When StartInteractiveLoginOptions does not set organization (defaults to None),
    the client-level default is used — same as before the fix.
    """
    mock_tx_store = AsyncMock()
    stored_tx = None

    async def capture_set(key, value, options=None):
        nonlocal stored_tx
        stored_tx = value

    mock_tx_store.set.side_effect = capture_set

    client = ServerClient(
        domain="tenant.auth0.com",
        client_id="cid",
        client_secret="csec",
        secret="test_secret_key_32_chars_long!!",
        organization="org_default",
        redirect_uri="https://app.example.com/callback",
        transaction_store=mock_tx_store,
        state_store=AsyncMock(),
    )
    mocker.patch.object(client, "_get_oidc_metadata_cached", return_value={
        "issuer": "https://tenant.auth0.com/",
        "authorization_endpoint": "https://tenant.auth0.com/authorize",
    })
    mocker.patch.object(client._oauth, "create_authorization_url",
                        return_value=("https://tenant.auth0.com/authorize?state=x", "x"))

    await client.start_interactive_login(StartInteractiveLoginOptions())

    assert stored_tx.organization == "org_default"

# =============================================================================
# IPSIE session_expiry enforcement
# =============================================================================


def test_is_session_ceiling_reached_none_never_expires():
    assert State.is_session_ceiling_reached(None) is False


def test_is_session_ceiling_reached_future_and_past():
    now = int(time.time())
    # Comfortably in the future (beyond the leeway window) -> not reached.
    assert State.is_session_ceiling_reached(now + 3600) is False
    # In the past -> reached.
    assert State.is_session_ceiling_reached(now - 10) is True


def test_is_session_ceiling_reached_applies_negative_leeway():
    now = int(time.time())
    # Ceiling is 10s away but leeway is 30s, so it's treated as already reached.
    assert State.is_session_ceiling_reached(now + 10) is True


def test_is_session_ceiling_in_past_none_is_safe_default():
    # No ceiling asserted -> never treated as expired.
    assert State.is_session_ceiling_in_past(None, 1893456000) is False
    assert State.is_session_ceiling_in_past(None, None) is False


def test_is_session_ceiling_in_past_past_ceiling_relative_to_iat():
    iat = 1893456000
    # Ceiling well before iat -> already lapsed at login.
    assert State.is_session_ceiling_in_past(iat - 3600, iat) is True


def test_is_session_ceiling_in_past_future_ceiling_relative_to_iat():
    iat = 1893456000
    # Ceiling well after iat -> not lapsed.
    assert State.is_session_ceiling_in_past(iat + 3600, iat) is False


def test_is_session_ceiling_in_past_falls_back_to_now_when_iat_absent():
    now = int(time.time())
    # No iat -> compare against wall-clock now; a past ceiling is lapsed.
    assert State.is_session_ceiling_in_past(now - 100, None) is True


def test_is_session_ceiling_in_past_leeway_boundary():
    iat = 1893456000
    leeway = State.SESSION_EXPIRY_LEEWAY_SECONDS
    # Ceiling exactly at iat + leeway is treated as already lapsed...
    assert State.is_session_ceiling_in_past(iat + leeway, iat) is True
    # ...one second beyond the leeway window is not.
    assert State.is_session_ceiling_in_past(iat + leeway + 1, iat) is False


def test_session_expired_error_message_is_generic():
    message = str(SessionExpiredError())
    # States the reason without leaking any timestamps or values.
    assert message == "The session has expired and the user must re-authenticate."
    assert not any(ch.isdigit() for ch in message)
    assert SessionExpiredError().code == AccessTokenErrorCode.SESSION_EXPIRED


@pytest.mark.parametrize("value,expected", [
    (1900000000, 1900000000),       # plausible seconds -> kept
    (1748566800000, None),          # milliseconds -> rejected
    (10_000_000_000, None),         # at the implausible-future bound -> rejected
    (0, None),                      # non-positive -> rejected
    (-5, None),                     # negative -> rejected
    (True, None),                   # bool is not a valid int here -> rejected
    ("1748566800", None),           # numeric string -> rejected
    ("not-a-number", None),         # garbage string -> rejected
    (1.5, None),                    # float -> rejected
    (None, None),                   # absent/null -> no ceiling
])
def test_user_claims_sanitizes_session_expiry(value, expected):
    assert UserClaims(sub="u", session_expiry=value).session_expiry == expected


def test_user_claims_session_expiry_absent_is_none():
    assert UserClaims(sub="u").session_expiry is None


def test_update_state_data_preserves_ceiling_across_refresh():
    now = int(time.time())
    ceiling = now + 3600
    existing_state = {
        "refresh_token": "refresh_xyz",
        "token_sets": [],
        "internal": {"sid": "some_sid", "created_at": now, "session_expires_at": ceiling},
    }
    # A refresh-token grant never carries session_expiry; the login ceiling stands.
    refresh_response = {"access_token": "new_token", "scope": "openid", "expires_in": 3600}

    updated = State.update_state_data("default", existing_state, refresh_response)

    assert updated["internal"]["session_expires_at"] == ceiling


@pytest.mark.asyncio
async def test_get_session_expired_by_ceiling_returns_none_and_deletes():
    now = int(time.time())
    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = {
        "user": {"sub": "user123"},
        "id_token": "token123",
        "internal": {"sid": "some_sid", "created_at": now - 100, "session_expires_at": now - 10},
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
    assert session_data is None
    mock_state_store.delete.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_session_within_ceiling_ok():
    now = int(time.time())
    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = {
        "user": {"sub": "user123"},
        "id_token": "token123",
        "internal": {"sid": "some_sid", "created_at": now, "session_expires_at": now + 3600},
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
    assert session_data is not None
    assert session_data["user"] == {"sub": "user123"}
    mock_state_store.delete.assert_not_awaited()


@pytest.mark.asyncio
async def test_get_user_expired_by_ceiling_returns_none_and_deletes():
    now = int(time.time())
    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = {
        "user": {"sub": "user123"},
        "internal": {"sid": "some_sid", "created_at": now - 100, "session_expires_at": now - 10},
    }

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
    mock_state_store.delete.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_user_no_ceiling_unaffected():
    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = {
        "user": {"sub": "user123"},
        "internal": {"sid": "some_sid", "created_at": int(time.time())},
    }

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
    mock_state_store.delete.assert_not_awaited()


@pytest.mark.asyncio
async def test_get_access_token_expired_by_ceiling_raises_without_refresh(mocker):
    now = int(time.time())
    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = {
        "refresh_token": "refresh_xyz",
        "token_sets": [
            {
                "audience": "default",
                "access_token": "cached_token",
                "expires_at": now + 500,  # still valid, but ceiling overrides
            }
        ],
        "internal": {"sid": "some_sid", "created_at": now - 100, "session_expires_at": now - 10},
    }

    client = ServerClient(
        domain="auth0.local",
        client_id="client_id",
        client_secret="client_secret",
        transaction_store=AsyncMock(),
        state_store=mock_state_store,
        secret="some-secret"
    )

    # If the refresh path is reached, that's a bug — make it explode.
    refresh_spy = mocker.patch.object(
        client, "get_token_by_refresh_token", new_callable=AsyncMock,
        side_effect=AssertionError("refresh must not be attempted after ceiling"),
    )

    with pytest.raises(SessionExpiredError) as exc:
        await client.get_access_token()

    assert exc.value.code == AccessTokenErrorCode.SESSION_EXPIRED
    refresh_spy.assert_not_awaited()
    mock_state_store.delete.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_access_token_within_ceiling_serves_cached():
    now = int(time.time())
    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = {
        "refresh_token": "refresh_xyz",
        "token_sets": [
            {
                "audience": "default",
                "access_token": "cached_token",
                "expires_at": now + 500,
            }
        ],
        "internal": {"sid": "some_sid", "created_at": now, "session_expires_at": now + 3600},
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
    assert token == "cached_token"
    mock_state_store.delete.assert_not_awaited()


@pytest.mark.asyncio
async def test_get_access_token_for_connection_not_gated_by_ceiling():
    # Token Vault connection tokens follow the upstream IdP's own expires_in,
    # so a passed session ceiling must NOT block or tear down the session here.
    now = int(time.time())
    mock_state_store = AsyncMock()
    mock_state_store.get.return_value = {
        "refresh_token": "refresh_xyz",
        "connection_token_sets": [
            {
                "connection": "google-oauth2",
                "login_hint": "user@example.com",
                "access_token": "cached_conn_token",
                "expires_at": now + 500,
            }
        ],
        "internal": {"sid": "some_sid", "created_at": now - 100, "session_expires_at": now - 10},
    }

    client = ServerClient(
        domain="auth0.local",
        client_id="client_id",
        client_secret="client_secret",
        transaction_store=AsyncMock(),
        state_store=mock_state_store,
        secret="some-secret"
    )

    token = await client.get_access_token_for_connection({"connection": "google-oauth2"})
    assert token == "cached_conn_token"
    mock_state_store.delete.assert_not_awaited()


@pytest.mark.asyncio
async def test_complete_interactive_login_rejects_already_expired_ceiling(mocker):
    """A session_expiry already in the past at login is rejected, not persisted."""
    iat = int(time.time())

    mock_tx_store = AsyncMock()
    mock_tx_store.get.return_value = TransactionData(
        code_verifier="123",
        domain="tenant.auth0.com",
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

    # Mock jwt.decode with a ceiling already in the past relative to iat
    mocker.patch("jwt.decode", return_value={
        "sub": "user123",
        "iss": "https://tenant.auth0.com/",
        "aud": "test_client",
        "iat": iat,
        "session_expiry": iat - 3600,
    })

    with pytest.raises(SessionExpiredError) as exc:
        await client.complete_interactive_login("http://localhost/callback?code=abc&state=xyz")

    assert exc.value.code == AccessTokenErrorCode.SESSION_EXPIRED
    # The already-expired session must never be persisted. The transaction is
    # cleaned up because its authorization code was already spent and cannot be
    # reused — a retry starts a fresh login with a new transaction.
    mock_state_store.set.assert_not_awaited()
    mock_tx_store.delete.assert_awaited_once()


@pytest.mark.asyncio
async def test_complete_interactive_login_future_ceiling_persists(mocker):
    """A future session_expiry is stamped on the session and login succeeds."""
    iat = int(time.time())
    ceiling = iat + 3600

    mock_tx_store = AsyncMock()
    mock_tx_store.get.return_value = TransactionData(
        code_verifier="123",
        domain="tenant.auth0.com",
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

    # Mock jwt.decode with a ceiling comfortably in the future
    mocker.patch("jwt.decode", return_value={
        "sub": "user123",
        "iss": "https://tenant.auth0.com/",
        "aud": "test_client",
        "iat": iat,
        "session_expiry": ceiling,
    })

    result = await client.complete_interactive_login("http://localhost/callback?code=abc&state=xyz")

    assert "state_data" in result
    mock_state_store.set.assert_awaited_once()
    stored_state = mock_state_store.set.call_args.args[1]
    assert stored_state.internal.session_expires_at == ceiling


@pytest.mark.asyncio
async def test_complete_interactive_login_no_ceiling_persists_normally(mocker):
    """No session_expiry claim -> login behaves exactly as before (no ceiling)."""
    iat = int(time.time())

    mock_tx_store = AsyncMock()
    mock_tx_store.get.return_value = TransactionData(
        code_verifier="123",
        domain="tenant.auth0.com",
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

    # Mock jwt.decode without a session_expiry claim
    mocker.patch("jwt.decode", return_value={
        "sub": "user123",
        "iss": "https://tenant.auth0.com/",
        "aud": "test_client",
        "iat": iat,
    })

    result = await client.complete_interactive_login("http://localhost/callback?code=abc&state=xyz")

    assert "state_data" in result
    mock_state_store.set.assert_awaited_once()
    stored_state = mock_state_store.set.call_args.args[1]
    assert stored_state.internal.session_expires_at is None


@pytest.mark.asyncio
async def test_complete_interactive_login_ignores_ceiling_from_userinfo(mocker):
    """The ceiling is read only from the verified ID token. A session_expiry
    present in the unverified userinfo response must NOT be persisted."""
    iat = int(time.time())

    mock_tx_store = AsyncMock()
    mock_tx_store.get.return_value = TransactionData(
        code_verifier="123",
        domain="tenant.auth0.com",
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

    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"issuer": "https://tenant.auth0.com/", "token_endpoint": "https://tenant.auth0.com/token"}
    )

    # fetch_token returns a userinfo dict (no id_token), driving the userinfo
    # branch. Its session_expiry must be ignored, not stamped on the session.
    async_fetch_token = AsyncMock()
    async_fetch_token.return_value = {
        "access_token": "token123",
        "scope": "openid profile",
        "userinfo": {
            "sub": "user123",
            "iat": iat,
            "session_expiry": iat + 3600,
        },
    }
    mocker.patch.object(client._oauth, "fetch_token", async_fetch_token)

    result = await client.complete_interactive_login("http://localhost/callback?code=abc&state=xyz")

    assert "state_data" in result
    mock_state_store.set.assert_awaited_once()
    stored_state = mock_state_store.set.call_args.args[1]
    assert stored_state.internal.session_expires_at is None


@pytest.mark.asyncio
async def test_complete_interactive_login_malformed_ceiling_fails_open(mocker):
    """A non-numeric session_expiry is treated as no ceiling, never a hard fail."""
    iat = int(time.time())

    mock_tx_store = AsyncMock()
    mock_tx_store.get.return_value = TransactionData(
        code_verifier="123",
        domain="tenant.auth0.com",
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

    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"issuer": "https://tenant.auth0.com/", "token_endpoint": "https://tenant.auth0.com/token"}
    )
    mocker.patch.object(
        client,
        "_get_jwks_cached",
        return_value={"keys": [{"kty": "RSA", "kid": "test-key"}]}
    )

    async_fetch_token = AsyncMock()
    async_fetch_token.return_value = {
        "access_token": "token123",
        "id_token": "id_token_jwt",
        "scope": "openid profile"
    }
    mocker.patch.object(client._oauth, "fetch_token", async_fetch_token)
    mocker.patch("jwt.get_unverified_header", return_value={"kid": "test-key"})
    mock_signing_key = mocker.MagicMock()
    mock_signing_key.key = "mock_pem_key"
    mocker.patch("jwt.PyJWK.from_dict", return_value=mock_signing_key)

    mocker.patch("jwt.decode", return_value={
        "sub": "user123",
        "iss": "https://tenant.auth0.com/",
        "aud": "test_client",
        "iat": iat,
        "session_expiry": "not-a-number",
    })

    # Must not raise — garbage claim degrades to no ceiling.
    result = await client.complete_interactive_login("http://localhost/callback?code=abc&state=xyz")

    assert "state_data" in result
    mock_state_store.set.assert_awaited_once()
    stored_state = mock_state_store.set.call_args.args[1]
    assert stored_state.internal.session_expires_at is None


@pytest.mark.asyncio
async def test_complete_interactive_login_milliseconds_ceiling_fails_open(mocker):
    """A millisecond-scale session_expiry is rejected as implausible -> no ceiling."""
    iat = int(time.time())

    mock_tx_store = AsyncMock()
    mock_tx_store.get.return_value = TransactionData(
        code_verifier="123",
        domain="tenant.auth0.com",
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

    mocker.patch.object(
        client,
        "_get_oidc_metadata_cached",
        return_value={"issuer": "https://tenant.auth0.com/", "token_endpoint": "https://tenant.auth0.com/token"}
    )
    mocker.patch.object(
        client,
        "_get_jwks_cached",
        return_value={"keys": [{"kty": "RSA", "kid": "test-key"}]}
    )

    async_fetch_token = AsyncMock()
    async_fetch_token.return_value = {
        "access_token": "token123",
        "id_token": "id_token_jwt",
        "scope": "openid profile"
    }
    mocker.patch.object(client._oauth, "fetch_token", async_fetch_token)
    mocker.patch("jwt.get_unverified_header", return_value={"kid": "test-key"})
    mock_signing_key = mocker.MagicMock()
    mock_signing_key.key = "mock_pem_key"
    mocker.patch("jwt.PyJWK.from_dict", return_value=mock_signing_key)

    mocker.patch("jwt.decode", return_value={
        "sub": "user123",
        "iss": "https://tenant.auth0.com/",
        "aud": "test_client",
        "iat": iat,
        "session_expiry": 1748566800000,
    })

    # Must not raise — a ms value is implausible as Unix seconds, so no ceiling.
    result = await client.complete_interactive_login("http://localhost/callback?code=abc&state=xyz")

    assert "state_data" in result
    mock_state_store.set.assert_awaited_once()
    stored_state = mock_state_store.set.call_args.args[1]
    assert stored_state.internal.session_expires_at is None
