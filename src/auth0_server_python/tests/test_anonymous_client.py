"""
Tests for AnonymousClient, covering anonymous session API operations.
"""

import base64 as _b64
import inspect
import time
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import urlsplit

import httpx
import pytest

from auth0_server_python.auth_server.anonymous_client import (
    ANON_IDENTIFIER,
    AnonymousClient,
)
from auth0_server_python.auth_types import (
    AnonymousSessionContext,
    AnonymousSessionData,
    AnonymousTokenSetEntry,
    CreateAnonymousSessionOptions,
)
from auth0_server_python.encryption.encrypt import encrypt
from auth0_server_python.error import (
    AnonymousSessionClientNotEnabledError,
    AnonymousSessionClientNotSupportedError,
    AnonymousSessionCreateError,
    AnonymousSessionFeatureNotEnabledError,
    AnonymousSessionResourceServerError,
    AnonymousSessionScopeError,
    AnonymousSessionTokenError,
    ConfigurationError,
    DomainResolverError,
)
from auth0_server_python.tests.store_fakes import OneSlotStore

# Shared fixtures
DOMAIN = "auth0.local"
CLIENT_ID = "<client_id>"
CLIENT_SECRET = "<client_secret>"
SECRET = "test-secret-long-enough-for-encryption"


def _make_client(anonymous_store=None, **kwargs) -> AnonymousClient:
    return AnonymousClient(
        domain=DOMAIN,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        secret=SECRET,
        anonymous_store=anonymous_store,
        **kwargs,
    )


def _fake_response(status_code=200, body=None):
    response = MagicMock()
    response.status_code = status_code
    response.json = MagicMock(return_value=body or {})
    return response


class _FakeAsyncClient:
    """Patches httpx.AsyncClient. Call sequence maps 1:1 to responses."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def __call__(self, *args, **kwargs):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        return self._responses.pop(0)

    async def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        return self._responses.pop(0)


def _token_response(
    access_token="AT1",  # noqa: S107
    expires_in=3600,
    session_token="ST1",  # noqa: S107
    session_expires_in=2592000,
):
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": expires_in,
        "session_token": session_token,
        "session_expires_in": session_expires_in,
    }


def _make_jwt(sub: str = "anon@test-uuid") -> str:
    """Build a minimal unsigned JWT with the given sub claim."""
    header = _b64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    payload = _b64.urlsafe_b64encode(f'{{"sub":"{sub}"}}'.encode()).rstrip(b"=").decode()
    return f"{header}.{payload}."


def _stored_context(store: OneSlotStore, **overrides):
    ts_keys = {"access_token", "expires_at", "audience", "scope"}
    ts_defaults = {
        "access_token": "AT1",
        "expires_at": int(time.time()) + 3600,
    }
    ctx_defaults = {
        "session_token": "ST1",
        "created_at": int(time.time()),
    }
    for k in list(overrides):
        if k in ts_keys:
            ts_defaults[k] = overrides.pop(k)
        else:
            ctx_defaults[k] = overrides.pop(k)
    token_set = AnonymousTokenSetEntry(**ts_defaults)
    context = AnonymousSessionContext(token_sets=[token_set], **ctx_defaults)
    encrypted = encrypt(context.model_dump(), SECRET, "anon_session")
    store.slot = (ANON_IDENTIFIER, {"context": encrypted})
    return context


# ── Constructor ──────────────────────────────────────────────────────────────

class TestAnonymousClientConstructor:
    def test_constructor_sets_properties(self):
        client = _make_client()
        assert client._domain == DOMAIN
        assert client._domain_resolver is None
        assert client._client_id == CLIENT_ID
        assert client._anonymous_store is None

    def test_constructor_accepts_callable_domain(self):
        resolver = AsyncMock(return_value="tenant.auth0.local")
        client = AnonymousClient(
            domain=resolver, client_id=CLIENT_ID, client_secret=CLIENT_SECRET, secret=SECRET
        )
        assert client._domain is None
        assert client._domain_resolver is resolver

    def test_no_dpop_key_parameter_exists(self):
        """Structural guard: AnonymousClient has no dpop_key parameter anywhere."""
        for name, method in inspect.getmembers(AnonymousClient, predicate=inspect.isfunction):
            sig = inspect.signature(method)
            assert "dpop_key" not in sig.parameters, f"{name} must never accept dpop_key"


# ── Fail-closed store isolation ───────────────────────────────────────────────

class TestStoreIsolation:
    @pytest.mark.asyncio
    async def test_create_session_without_store_raises_configuration_error(self):
        client = _make_client(anonymous_store=None)
        with pytest.raises(ConfigurationError):
            await client.create_session(audience="aud", scope="s")

    @pytest.mark.asyncio
    async def test_get_token_without_store_raises_configuration_error(self):
        client = _make_client(anonymous_store=None)
        with pytest.raises(ConfigurationError):
            await client.get_token()

    @pytest.mark.asyncio
    async def test_logout_without_store_raises_configuration_error(self):
        client = _make_client(anonymous_store=None)
        with pytest.raises(ConfigurationError):
            await client.logout()

    @pytest.mark.asyncio
    async def test_no_write_attempted_when_store_missing(self):
        """Fails closed before any store write, never falls back to another store."""
        client = _make_client(anonymous_store=None)
        with patch("httpx.AsyncClient") as mock_http:
            with pytest.raises(ConfigurationError):
                await client.create_session(audience="aud", scope="s")
            mock_http.assert_not_called()


# ── create_session ────────────────────────────────────────────────────────────

class TestCreateSession:
    @pytest.mark.asyncio
    async def test_create_session_success(self):
        store = OneSlotStore()
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([_fake_response(200, _token_response())])
        with patch("httpx.AsyncClient", fake_http):
            session = await client.create_session(
                audience="https://api.example.com", scope="read:cart", metadata={"cart_id": "c1"}
            )
        assert session.metadata == {"cart_id": "c1"}

    @pytest.mark.asyncio
    async def test_create_session_exposes_session_token_to_caller(self):
        """create_session() must expose session_token to the caller."""
        store = OneSlotStore()
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([_fake_response(200, _token_response())])
        with patch("httpx.AsyncClient", fake_http):
            session = await client.create_session(audience="aud", scope="s")
        assert session.session_token == "ST1"

    @pytest.mark.asyncio
    async def test_get_token_exposes_session_token_on_cached_and_reminted_paths(self):
        """get_token() must carry session_token on both cached and re-minted paths."""
        store = OneSlotStore()
        client = _make_client(anonymous_store=store)

        _stored_context(store)
        cached = await client.get_token()
        assert cached.session_token == "ST1"

        _stored_context(store, expires_at=int(time.time()) - 10)
        fake_http = _FakeAsyncClient(
            [_fake_response(200, _token_response(access_token="AT2", session_token="ST2"))]
        )
        with patch("httpx.AsyncClient", fake_http):
            reminted = await client.get_token()
        assert reminted.session_token == "ST2"

    @pytest.mark.asyncio
    async def test_remint_without_session_token_keeps_exposing_prior_token(self):
        """Re-mint response omitting session_token must keep exposing the prior one."""
        store = OneSlotStore()
        client = _make_client(anonymous_store=store)
        _stored_context(store, expires_at=int(time.time()) - 10)
        response = _token_response(access_token="AT2")
        del response["session_token"]
        fake_http = _FakeAsyncClient([_fake_response(200, response)])
        with patch("httpx.AsyncClient", fake_http):
            session = await client.get_token()
        assert session.session_token == "ST1"

    @pytest.mark.asyncio
    async def test_create_session_response_missing_session_token_raises(self):
        store = OneSlotStore()
        client = _make_client(anonymous_store=store)
        response_without_session_token = _token_response()
        del response_without_session_token["session_token"]
        fake_http = _FakeAsyncClient([_fake_response(200, response_without_session_token)])
        with patch("httpx.AsyncClient", fake_http):
            with pytest.raises(AnonymousSessionCreateError) as excinfo:
                await client.create_session(audience="aud", scope="s")
        assert excinfo.value.code == "missing_session_token"
        assert store.slot is None

    @pytest.mark.asyncio
    async def test_create_session_sends_client_secret_in_json_body_not_auth_tuple(self):
        store = OneSlotStore()
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([_fake_response(200, _token_response())])
        with patch("httpx.AsyncClient", fake_http):
            await client.create_session(audience="aud", scope="s")
        _, _, kwargs = fake_http.calls[0]
        assert kwargs["json"]["client_secret"] == CLIENT_SECRET
        assert "auth" not in kwargs

    @pytest.mark.asyncio
    async def test_create_session_never_attaches_dpop_header(self):
        store = OneSlotStore()
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([_fake_response(200, _token_response())])
        with patch("httpx.AsyncClient", fake_http):
            await client.create_session(audience="aud", scope="s")
        _, _, kwargs = fake_http.calls[0]
        assert "DPoP" not in kwargs.get("headers", {})

    @pytest.mark.asyncio
    async def test_create_session_persists_at_distinct_location_from_state_store(self):
        """The anonymous store instance is separate from any authenticated session store."""
        anon_store = OneSlotStore()
        state_store = OneSlotStore()
        state_store.slot = ("_a0_session", {"user": "authenticated"})
        client = _make_client(anonymous_store=anon_store)
        fake_http = _FakeAsyncClient([_fake_response(200, _token_response())])
        with patch("httpx.AsyncClient", fake_http):
            await client.create_session(audience="aud", scope="s")
        assert anon_store.slot[0] == ANON_IDENTIFIER
        assert state_store.slot == ("_a0_session", {"user": "authenticated"})

    @pytest.mark.asyncio
    async def test_metadata_over_1kb_rejected_client_side_no_network_call(self):
        store = OneSlotStore()
        client = _make_client(anonymous_store=store)
        oversized = {"blob": "x" * 2000}
        with patch("httpx.AsyncClient") as mock_http:
            with pytest.raises(AnonymousSessionCreateError, match="1KB"):
                await client.create_session(audience="aud", scope="s", metadata=oversized)
            mock_http.assert_not_called()

    @pytest.mark.asyncio
    async def test_dangerous_metadata_key_rejected(self):
        store = OneSlotStore()
        client = _make_client(anonymous_store=store)
        with pytest.raises(AnonymousSessionCreateError, match="not allowed"):
            await client.create_session(audience="aud", scope="s", metadata={"__proto__": "x"})

    @pytest.mark.asyncio
    async def test_non_string_metadata_value_accepted(self):
        store = OneSlotStore()
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([_fake_response(200, _token_response())])
        with patch("httpx.AsyncClient", fake_http):
            await client.create_session(
                audience="aud", scope="s", metadata={"count": 5, "active": True, "tags": ["a", "b"]}
            )
        _, _, kwargs = fake_http.calls[0]
        assert kwargs["json"]["metadata"] == {"count": 5, "active": True, "tags": ["a", "b"]}

    @pytest.mark.asyncio
    async def test_non_json_serializable_metadata_value_rejected(self):
        store = OneSlotStore()
        client = _make_client(anonymous_store=store)
        with pytest.raises(AnonymousSessionCreateError, match="JSON-serializable"):
            await client.create_session(audience="aud", scope="s", metadata={"bad": object()})

    @pytest.mark.asyncio
    async def test_create_session_accepts_options_model(self):
        store = OneSlotStore()
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([_fake_response(200, _token_response())])
        options = CreateAnonymousSessionOptions(
            audience="aud", scope="s", metadata={"cart_id": "c1"}
        )
        with patch("httpx.AsyncClient", fake_http):
            await client.create_session(options=options)
        _, _, kwargs = fake_http.calls[0]
        assert kwargs["json"]["audience"] == "aud"
        assert kwargs["json"]["scope"] == "s"
        assert kwargs["json"]["metadata"] == {"cart_id": "c1"}

    @pytest.mark.asyncio
    async def test_create_session_accepts_options_dict(self):
        store = OneSlotStore()
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([_fake_response(200, _token_response())])
        with patch("httpx.AsyncClient", fake_http):
            await client.create_session(options={"audience": "aud", "scope": "s"})
        _, _, kwargs = fake_http.calls[0]
        assert kwargs["json"]["audience"] == "aud"
        assert kwargs["json"]["scope"] == "s"

    @pytest.mark.asyncio
    async def test_explicit_kwargs_override_options(self):
        store = OneSlotStore()
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([_fake_response(200, _token_response())])
        with patch("httpx.AsyncClient", fake_http):
            await client.create_session(
                options={"audience": "from_options"}, audience="from_kwarg"
            )
        _, _, kwargs = fake_http.calls[0]
        assert kwargs["json"]["audience"] == "from_kwarg"

    @pytest.mark.asyncio
    async def test_invalid_options_dict_raises_typed_error_no_network_call(self):
        store = OneSlotStore()
        client = _make_client(anonymous_store=store)
        with patch("httpx.AsyncClient") as mock_http:
            with pytest.raises(AnonymousSessionCreateError) as exc:
                await client.create_session(options={"unknown_field": "x"})
            assert exc.value.code == "invalid_options"
            mock_http.assert_not_called()

    @pytest.mark.asyncio
    async def test_feature_not_enabled_maps_to_typed_error(self):
        store = OneSlotStore()
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([
            _fake_response(403, {"error": "feature_not_enabled", "error_description": "disabled"})
        ])
        with patch("httpx.AsyncClient", fake_http):
            with pytest.raises(AnonymousSessionFeatureNotEnabledError):
                await client.create_session(audience="aud", scope="s")

    @pytest.mark.asyncio
    async def test_unauthorized_client_maps_to_typed_error(self):
        store = OneSlotStore()
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([
            _fake_response(403, {"error": "unauthorized_client", "error_description": "not enabled"})
        ])
        with patch("httpx.AsyncClient", fake_http):
            with pytest.raises(AnonymousSessionClientNotEnabledError):
                await client.create_session(audience="aud", scope="s")

    @pytest.mark.asyncio
    async def test_dpop_required_client_maps_to_not_supported_with_literal_message(self):
        store = OneSlotStore()
        client = _make_client(anonymous_store=store)
        message = "Client configuration requires the use of Proof-of-Possession mechanism"
        fake_http = _FakeAsyncClient([
            _fake_response(400, {"error": "unauthorized_client", "error_description": message})
        ])
        with patch("httpx.AsyncClient", fake_http):
            with pytest.raises(AnonymousSessionClientNotSupportedError) as exc:
                await client.create_session(audience="aud", scope="s")
        assert message in str(exc.value)

    @pytest.mark.asyncio
    async def test_invalid_target_maps_to_resource_server_error(self):
        store = OneSlotStore()
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([
            _fake_response(400, {"error": "invalid_target", "error_description": "bad audience"})
        ])
        with patch("httpx.AsyncClient", fake_http):
            with pytest.raises(AnonymousSessionResourceServerError):
                await client.create_session(audience="aud", scope="s")

    @pytest.mark.asyncio
    async def test_invalid_scope_maps_to_scope_error(self):
        store = OneSlotStore()
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([
            _fake_response(400, {"error": "invalid_scope", "error_description": "bad scope"})
        ])
        with patch("httpx.AsyncClient", fake_http):
            with pytest.raises(AnonymousSessionScopeError):
                await client.create_session(audience="aud", scope="s")

    @pytest.mark.asyncio
    async def test_network_failure_raises_create_error(self):
        store = OneSlotStore()
        client = _make_client(anonymous_store=store)

        class _RaisingClient:
            def __call__(self, *a, **k):
                return self

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def post(self, *a, **k):
                raise httpx.ConnectError("boom")

        with patch("httpx.AsyncClient", _RaisingClient()):
            with pytest.raises(AnonymousSessionCreateError):
                await client.create_session(audience="aud", scope="s")


    @pytest.mark.asyncio
    async def test_create_session_stores_and_returns_sub_from_jwt(self):
        store = OneSlotStore()
        client = _make_client(anonymous_store=store)
        jwt_token = _make_jwt("anon@test-uuid")
        fake_http = _FakeAsyncClient([_fake_response(200, {
            "access_token": jwt_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "session_token": "ST1",
            "session_expires_in": 2592000,
        })])
        with patch("httpx.AsyncClient", fake_http):
            session = await client.create_session()
        assert session.sub == "anon@test-uuid"
        stored = await store.get(ANON_IDENTIFIER)
        ctx = client._decrypt_context(stored)
        assert ctx.sub == "anon@test-uuid"

    @pytest.mark.asyncio
    async def test_create_session_stores_none_sub_for_opaque_token(self):
        store = OneSlotStore()
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([_fake_response(200, {
            "access_token": "opaque.token.without.claims.here",
            "token_type": "Bearer",
            "expires_in": 3600,
            "session_token": "ST1",
            "session_expires_in": 2592000,
        })])
        with patch("httpx.AsyncClient", fake_http):
            session = await client.create_session()
        assert session.sub is None
        stored = await store.get(ANON_IDENTIFIER)
        ctx = client._decrypt_context(stored)
        assert ctx.sub is None


# ── get_token (renewal ladder) ────────────────────────────────────────────────

class TestGetToken:
    @pytest.mark.asyncio
    async def test_fresh_cached_token_returned_with_no_http_call(self):
        store = OneSlotStore()
        _stored_context(store, expires_at=int(time.time()) + 3600)
        client = _make_client(anonymous_store=store)
        with patch("httpx.AsyncClient") as mock_http:
            session = await client.get_token()
            mock_http.assert_not_called()
        assert session.access_token == "AT1"

    @pytest.mark.asyncio
    async def test_no_active_session_raises_token_error(self):
        store = OneSlotStore()
        client = _make_client(anonymous_store=store)
        with pytest.raises(AnonymousSessionTokenError):
            await client.get_token()

    @pytest.mark.asyncio
    async def test_expired_access_token_remints_via_session_token_grant(self):
        store = OneSlotStore()
        _stored_context(store, expires_at=int(time.time()) - 10)
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([
            _fake_response(
                200,
                {
                    "access_token": "AT2",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "session_expires_in": 2592000,
                },
            )
        ])
        with patch("httpx.AsyncClient", fake_http):
            session = await client.get_token()
        assert session.access_token == "AT2"
        _, _, kwargs = fake_http.calls[0]
        assert kwargs["json"]["session_token"] == "ST1"
        assert "refresh_token" not in kwargs["json"]

    @pytest.mark.asyncio
    async def test_remint_replays_audience_and_scope_from_get_token_params(self):
        """Re-mint request must include the audience/scope passed to get_token."""
        store = OneSlotStore()
        _stored_context(store, expires_at=int(time.time()) - 10)
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([
            _fake_response(
                200,
                {
                    "access_token": "AT2",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "session_expires_in": 2592000,
                },
            )
        ])
        with patch("httpx.AsyncClient", fake_http):
            await client.get_token(audience="https://api.example.com", scope="read:things")
        _, _, kwargs = fake_http.calls[0]
        assert kwargs["json"]["audience"] == "https://api.example.com"
        assert kwargs["json"]["scope"] == "read:things"

    @pytest.mark.asyncio
    async def test_remint_omits_audience_and_scope_when_the_session_had_none(self):
        """Absent values must stay absent - never sent as null or empty string."""
        store = OneSlotStore()
        _stored_context(store, expires_at=int(time.time()) - 10)
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([
            _fake_response(
                200,
                {
                    "access_token": "AT2",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "session_expires_in": 2592000,
                },
            )
        ])
        with patch("httpx.AsyncClient", fake_http):
            await client.get_token()
        _, _, kwargs = fake_http.calls[0]
        assert "audience" not in kwargs["json"]
        assert "scope" not in kwargs["json"]

    @pytest.mark.asyncio
    async def test_remint_preserves_empty_string_fields_instead_of_falling_back_to_stale_context(
        self,
    ):
        store = OneSlotStore()
        _stored_context(store, expires_at=int(time.time()) - 10)
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([
            _fake_response(
                200,
                {
                    "access_token": "AT2",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "session_expires_in": 2592000,
                    "session_token": "",
                },
            )
        ])
        with patch("httpx.AsyncClient", fake_http):
            await client.get_token()
        stored = await store.get(ANON_IDENTIFIER)
        context = client._decrypt_context(stored)
        assert context.session_token == ""

    @pytest.mark.asyncio
    async def test_expired_session_token_triggers_silent_new_session(self):
        store = OneSlotStore()
        _stored_context(store, expires_at=int(time.time()) - 10)
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([
            _fake_response(400, {"error": "session_expired", "error_description": "expired"}),
            _fake_response(200, _token_response()),
        ])
        with patch("httpx.AsyncClient", fake_http):
            await client.get_token()
        assert len(fake_http.calls) == 2

    @pytest.mark.asyncio
    async def test_silent_remint_drops_metadata(self):
        store = OneSlotStore()
        _stored_context(store, expires_at=int(time.time()) - 10, metadata={"cart_id": "c1"})
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([
            _fake_response(400, {"error": "invalid_session_token", "error_description": "bad"}),
            _fake_response(200, _token_response()),
        ])
        with patch("httpx.AsyncClient", fake_http):
            session = await client.get_token()
        assert session.metadata is None

    @pytest.mark.asyncio
    async def test_two_consecutive_session_expired_raises_not_loops(self):
        """Retry-once bound: exactly 2 upstream POSTs, then raise."""
        store = OneSlotStore()
        _stored_context(store, expires_at=int(time.time()) - 10)
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([
            _fake_response(400, {"error": "session_expired", "error_description": "expired"}),
            _fake_response(400, {"error": "session_expired", "error_description": "expired again"}),
        ])
        with patch("httpx.AsyncClient", fake_http):
            with pytest.raises(AnonymousSessionCreateError):
                await client.get_token()
        assert len(fake_http.calls) == 2

    @pytest.mark.asyncio
    async def test_other_error_code_raises_typed_error_no_retry(self):
        store = OneSlotStore()
        _stored_context(store, expires_at=int(time.time()) - 10)
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([
            _fake_response(403, {"error": "feature_not_enabled", "error_description": "off"}),
        ])
        with patch("httpx.AsyncClient", fake_http):
            with pytest.raises(AnonymousSessionFeatureNotEnabledError):
                await client.get_token()
        assert len(fake_http.calls) == 1

    @pytest.mark.asyncio
    async def test_corrupted_stored_token_triggers_silent_new_session(self):
        store = OneSlotStore()
        store.slot = (ANON_IDENTIFIER, {"context": "not-a-valid-jwe"})
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([_fake_response(200, _token_response())])
        with patch("httpx.AsyncClient", fake_http):
            session = await client.get_token()
        assert session.access_token == "AT1"
        assert len(fake_http.calls) == 1

    @pytest.mark.asyncio
    async def test_network_error_during_renewal_not_misclassified_as_expiry(self):
        """A broad exception must never be silently treated as session_expired."""
        store = OneSlotStore()
        _stored_context(store, expires_at=int(time.time()) - 10)
        client = _make_client(anonymous_store=store)

        class _RaisingClient:
            def __call__(self, *a, **k):
                return self

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def post(self, *a, **k):
                raise httpx.ConnectError("network down")

        with patch("httpx.AsyncClient", _RaisingClient()):
            with pytest.raises(AnonymousSessionTokenError):
                await client.get_token()

    @pytest.mark.asyncio
    async def test_get_token_never_writes_to_authenticated_state_store(self):
        anon_store = OneSlotStore()
        _stored_context(anon_store, expires_at=int(time.time()) + 3600)
        auth_state_store = AsyncMock()
        client = _make_client(anonymous_store=anon_store)
        await client.get_token()
        auth_state_store.set.assert_not_called()
        auth_state_store.get.assert_not_called()
        auth_state_store.delete.assert_not_called()

    @pytest.mark.asyncio
    async def test_second_audience_is_cached_without_evicting_first(self):
        """get_token for a different audience upserts rather than replacing."""
        store = OneSlotStore()
        _stored_context(store, audience="https://api1.example.com")
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([
            _fake_response(200, {
                "access_token": "AT2",
                "token_type": "Bearer",
                "expires_in": 3600,
                "session_expires_in": 2592000,
            })
        ])
        with patch("httpx.AsyncClient", fake_http):
            await client.get_token(audience="https://api2.example.com")

        stored = await store.get(ANON_IDENTIFIER)
        context = client._decrypt_context(stored)
        audiences = [ts.audience for ts in context.token_sets]
        assert any(a == "https://api1.example.com" for a in audiences)
        assert any(a == "https://api2.example.com" for a in audiences)

    @pytest.mark.asyncio
    async def test_cached_token_returned_for_correct_audience(self):
        """get_token returns the cached token for the matching audience without a network call."""
        store = OneSlotStore()
        _stored_context(store, audience="https://api1.example.com", access_token="AT_API1")
        client = _make_client(anonymous_store=store)
        with patch("httpx.AsyncClient") as mock_http:
            session = await client.get_token(audience="https://api1.example.com")
            mock_http.assert_not_called()
        assert session.access_token == "AT_API1"

    @pytest.mark.asyncio
    async def test_different_audience_causes_remint_not_cache_hit(self):
        """A stored token for api1 does not satisfy a request for api2."""
        store = OneSlotStore()
        _stored_context(store, audience="https://api1.example.com", access_token="AT_API1")
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([
            _fake_response(200, {
                "access_token": "AT_API2",
                "token_type": "Bearer",
                "expires_in": 3600,
                "session_expires_in": 2592000,
            })
        ])
        with patch("httpx.AsyncClient", fake_http):
            session = await client.get_token(audience="https://api2.example.com")
        assert session.access_token == "AT_API2"
        assert len(fake_http.calls) == 1

    @pytest.mark.asyncio
    async def test_concurrent_remint_preserves_other_audience_token(self):
        """A token for api2 written to the store before our re-read is not lost."""
        store = OneSlotStore()
        _stored_context(store)
        client = _make_client(anonymous_store=store)

        remint_response = {
            "access_token": "AT_API1",
            "token_type": "Bearer",
            "expires_in": 3600,
            "session_expires_in": 2592000,
        }

        original_get = store.get
        original_set = store.set
        get_call_count = 0

        async def get_with_concurrent_write(identifier, *, options=None):
            nonlocal get_call_count
            get_call_count += 1
            if get_call_count == 2:
                # Simulate a concurrent remint for api2 completing during our HTTP call,
                # i.e. before our re-read runs.
                current = await original_get(identifier)
                ctx = client._decrypt_context(current)
                concurrent_token_set = AnonymousTokenSetEntry(
                    access_token="AT_API2",
                    expires_at=int(time.time()) + 3600,
                    audience="https://api2.example.com",
                )
                merged = client._upsert_token_set(ctx, concurrent_token_set)
                await original_set(
                    identifier,
                    {"context": encrypt(merged.model_dump(), SECRET, "anon_session")},
                )
            return await original_get(identifier)

        store.get = get_with_concurrent_write

        fake_http = _FakeAsyncClient([_fake_response(200, remint_response)])
        with patch("httpx.AsyncClient", fake_http):
            await client.get_token(audience="https://api1.example.com")

        stored = await store.get(ANON_IDENTIFIER)
        final_ctx = client._decrypt_context(stored)
        audiences = [ts.audience for ts in final_ctx.token_sets]
        assert any(a == "https://api2.example.com" for a in audiences)
        assert any(a == "https://api1.example.com" for a in audiences)

    @pytest.mark.asyncio
    async def test_remint_skips_write_when_session_deleted_during_fetch(self):
        """If the session is deleted while the HTTP call is in flight, the write is skipped."""
        store = OneSlotStore()
        _stored_context(store, expires_at=int(time.time()) - 10)
        client = _make_client(anonymous_store=store)

        original_get = store.get
        call_count = 0

        async def get_and_delete(identifier, *, options=None):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                store.slot = None
            return await original_get(identifier)

        store.get = get_and_delete
        fake_http = _FakeAsyncClient([
            _fake_response(200, {
                "access_token": "AT2",
                "token_type": "Bearer",
                "expires_in": 3600,
                "session_expires_in": 2592000,
            })
        ])
        with patch("httpx.AsyncClient", fake_http):
            session = await client.get_token()

        assert session is not None
        assert store.slot is None

    @pytest.mark.asyncio
    async def test_remint_skips_write_when_session_replaced_during_fetch(self):
        """If the session token changed while in flight (recreation), the write is skipped."""
        store = OneSlotStore()
        _stored_context(store, expires_at=int(time.time()) - 10)
        client = _make_client(anonymous_store=store)

        original_get = store.get
        call_count = 0

        async def get_and_replace(identifier, *, options=None):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                _stored_context(store, session_token="NEW_SESSION_TOKEN")
            return await original_get(identifier)

        store.get = get_and_replace
        fake_http = _FakeAsyncClient([
            _fake_response(200, {
                "access_token": "AT2",
                "token_type": "Bearer",
                "expires_in": 3600,
                "session_expires_in": 2592000,
            })
        ])
        with patch("httpx.AsyncClient", fake_http):
            session = await client.get_token()

        assert session is not None
        stored = await store.get(ANON_IDENTIFIER)
        final_ctx = client._decrypt_context(stored)
        assert final_ctx.session_token == "NEW_SESSION_TOKEN"

    @pytest.mark.asyncio
    async def test_get_token_returns_sub_from_cache(self):
        store = OneSlotStore()
        _stored_context(store, sub="anon@cached-uuid")
        client = _make_client(anonymous_store=store)
        with patch("httpx.AsyncClient") as mock_http:
            session = await client.get_token()
            mock_http.assert_not_called()
        assert session.sub == "anon@cached-uuid"

    @pytest.mark.asyncio
    async def test_remint_returns_and_stores_sub_from_new_token(self):
        store = OneSlotStore()
        _stored_context(store, expires_at=int(time.time()) - 10)
        client = _make_client(anonymous_store=store)
        jwt_token = _make_jwt("anon@reminted-uuid")
        fake_http = _FakeAsyncClient([_fake_response(200, {
            "access_token": jwt_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "session_expires_in": 2592000,
        })])
        with patch("httpx.AsyncClient", fake_http):
            session = await client.get_token()
        assert session.sub == "anon@reminted-uuid"
        stored = await store.get(ANON_IDENTIFIER)
        ctx = client._decrypt_context(stored)
        assert ctx.sub == "anon@reminted-uuid"

    @pytest.mark.asyncio
    async def test_remint_does_not_overwrite_existing_sub(self):
        """Once sub is stored, a remint that returns a readable token must not replace it."""
        store = OneSlotStore()
        _stored_context(store, expires_at=int(time.time()) - 10, sub="anon@original-uuid")
        client = _make_client(anonymous_store=store)
        jwt_token = _make_jwt("anon@should-be-ignored")
        fake_http = _FakeAsyncClient([_fake_response(200, {
            "access_token": jwt_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "session_expires_in": 2592000,
        })])
        with patch("httpx.AsyncClient", fake_http):
            await client.get_token()
        stored = await store.get(ANON_IDENTIFIER)
        ctx = client._decrypt_context(stored)
        assert ctx.sub == "anon@original-uuid"


# ── MCD / cross-tenant isolation ───────────────────────────────────────────────

class TestMcdIsolation:
    @pytest.mark.asyncio
    async def test_domain_mismatch_in_resolver_mode_mints_fresh_under_current_tenant(self):
        store = OneSlotStore()
        _stored_context(
            store, expires_at=int(time.time()) + 3600, domain="tenant-a.auth0.local"
        )
        resolver = AsyncMock(return_value="tenant-b.auth0.local")
        client = _make_client(anonymous_store=store)
        client._domain_resolver = resolver
        client._domain = None
        fake_http = _FakeAsyncClient([_fake_response(200, _token_response())])
        with patch("httpx.AsyncClient", fake_http):
            await client.get_token()
        _, url, _ = fake_http.calls[0]
        assert urlsplit(url).hostname == "tenant-b.auth0.local"

    @pytest.mark.asyncio
    async def test_domain_mismatch_in_static_mode_mints_fresh_under_current_tenant(self):
        store = OneSlotStore()
        _stored_context(
            store, expires_at=int(time.time()) + 3600, domain="tenant-a.auth0.local"
        )
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([_fake_response(200, _token_response())])
        with patch("httpx.AsyncClient", fake_http):
            await client.get_token()
        _, url, _ = fake_http.calls[0]
        assert urlsplit(url).hostname != "tenant-a.auth0.local"

    @pytest.mark.asyncio
    async def test_domain_mismatch_remint_preserves_metadata(self):
        """A domain-mismatch re-mint must carry the stored metadata, not drop the cart."""
        store = OneSlotStore()
        _stored_context(
            store,
            expires_at=int(time.time()) + 3600,
            domain="tenant-a.auth0.local",
            metadata={"cart": ["sku-1"]},
        )
        resolver = AsyncMock(return_value="tenant-b.auth0.local")
        client = _make_client(anonymous_store=store)
        client._domain_resolver = resolver
        client._domain = None
        fake_http = _FakeAsyncClient([_fake_response(200, _token_response())])
        with patch("httpx.AsyncClient", fake_http):
            await client.get_token()
        _, url, kwargs = fake_http.calls[0]
        assert urlsplit(url).hostname == "tenant-b.auth0.local"
        assert kwargs["json"]["metadata"] == {"cart": ["sku-1"]}

    @pytest.mark.asyncio
    async def test_domain_resolver_failure_propagates(self):
        resolver = AsyncMock(return_value=None)
        client = AnonymousClient(
            domain=resolver, client_id=CLIENT_ID, client_secret=CLIENT_SECRET, secret=SECRET,
            anonymous_store=OneSlotStore(),
        )
        with pytest.raises(DomainResolverError):
            await client.create_session(audience="aud", scope="s")


# ── logout ────────────────────────────────────────────────────────────────────

class TestLogout:
    @pytest.mark.asyncio
    async def test_logout_clears_anonymous_store(self):
        store = OneSlotStore()
        _stored_context(store)
        client = _make_client(anonymous_store=store)
        await client.logout()
        assert store.slot is None

    @pytest.mark.asyncio
    async def test_logout_does_not_touch_unrelated_authenticated_store(self):
        anon_store = OneSlotStore()
        _stored_context(anon_store)
        auth_store = AsyncMock()
        client = _make_client(anonymous_store=anon_store)
        await client.logout()
        auth_store.delete.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_token_after_logout_behaves_as_no_session(self):
        store = OneSlotStore()
        _stored_context(store)
        client = _make_client(anonymous_store=store)
        await client.logout()
        with pytest.raises(AnonymousSessionTokenError):
            await client.get_token()

    @pytest.mark.asyncio
    async def test_logout_with_no_session_is_a_noop(self):
        store = OneSlotStore()
        client = _make_client(anonymous_store=store)
        await client.logout()
        assert store.slot is None

    @pytest.mark.asyncio
    async def test_logout_corrupted_context_clears_state(self):
        store = OneSlotStore()
        store.slot = (ANON_IDENTIFIER, {"context": "not-a-decryptable-blob"})
        client = _make_client(anonymous_store=store)
        await client.logout()
        assert store.slot is None


# ── exchange_transfer_token_for_injection (transfer ticket) ─────────────────────

_TRANSFER_OK = {"token_type": "N_A", "anon_transfer_token": "TICKET", "expires_in": 30}


class TestExchangeTransferTokenForInjection:
    @pytest.mark.asyncio
    async def test_success_returns_ticket_with_correct_request_body(self):
        store = OneSlotStore()
        _stored_context(store, session_token="REAL_TOKEN", domain="auth0.local")
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([_fake_response(200, _TRANSFER_OK)])
        with patch("httpx.AsyncClient", fake_http):
            ticket = await client.exchange_transfer_token_for_injection("auth0.local")
        assert ticket == "TICKET"
        method, url, kwargs = fake_http.calls[0]
        assert method == "POST"
        assert url == "https://auth0.local/anonymous/token"
        body = kwargs["json"]
        assert body["audience"] == "urn:auth0:anon_transfer"
        assert body["session_token"] == "REAL_TOKEN"
        assert body["client_id"] == CLIENT_ID
        assert body["client_secret"] == CLIENT_SECRET

    @pytest.mark.asyncio
    async def test_missing_context_domain_mints_against_origin(self):
        """A stored context with no domain is not an MCD mismatch, so mint against origin."""
        store = OneSlotStore()
        _stored_context(store, session_token="REAL_TOKEN")  # domain defaults to None
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([_fake_response(200, _TRANSFER_OK)])
        with patch("httpx.AsyncClient", fake_http):
            ticket = await client.exchange_transfer_token_for_injection("auth0.local")
        assert ticket == "TICKET"
        _, url, _ = fake_http.calls[0]
        assert urlsplit(url).hostname == "auth0.local"

    @pytest.mark.asyncio
    async def test_returns_none_without_store(self):
        client = _make_client(anonymous_store=None)
        assert await client.exchange_transfer_token_for_injection("auth0.local") is None

    @pytest.mark.asyncio
    async def test_returns_none_when_no_session_no_http(self):
        store = OneSlotStore()
        client = _make_client(anonymous_store=store)
        with patch("httpx.AsyncClient") as mock_http:
            assert await client.exchange_transfer_token_for_injection("auth0.local") is None
            mock_http.assert_not_called()

    @pytest.mark.asyncio
    async def test_returns_none_on_corrupted_context(self):
        store = OneSlotStore()
        store.slot = (ANON_IDENTIFIER, {"context": "garbage"})
        client = _make_client(anonymous_store=store)
        assert await client.exchange_transfer_token_for_injection("auth0.local") is None

    @pytest.mark.asyncio
    async def test_domain_mismatch_fails_closed_no_mint(self):
        """MCD fail-closed: never mint a ticket for a host the session was not created against."""
        store = OneSlotStore()
        _stored_context(store, domain="tenant-a.auth0.local")
        client = _make_client(anonymous_store=store)
        with patch("httpx.AsyncClient") as mock_http:
            result = await client.exchange_transfer_token_for_injection("tenant-b.auth0.local")
            assert result is None
            mock_http.assert_not_called()

    @pytest.mark.asyncio
    async def test_returns_none_on_non_200(self):
        store = OneSlotStore()
        _stored_context(store, domain="auth0.local")
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([_fake_response(400, {"error": "invalid_request"})])
        with patch("httpx.AsyncClient", fake_http):
            assert await client.exchange_transfer_token_for_injection("auth0.local") is None

    @pytest.mark.asyncio
    async def test_returns_none_on_network_error(self):
        store = OneSlotStore()
        _stored_context(store, domain="auth0.local")
        client = _make_client(anonymous_store=store)

        class _Boom:
            def __call__(self, *a, **k):
                return self

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def post(self, *a, **k):
                raise httpx.ConnectError("boom")

        with patch("httpx.AsyncClient", _Boom()):
            assert await client.exchange_transfer_token_for_injection("auth0.local") is None

    @pytest.mark.asyncio
    async def test_returns_none_on_invalid_response_shape(self):
        store = OneSlotStore()
        _stored_context(store, domain="auth0.local")
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([_fake_response(200, {"token_type": "N_A", "expires_in": 30})])
        with patch("httpx.AsyncClient", fake_http):
            assert await client.exchange_transfer_token_for_injection("auth0.local") is None

    @pytest.mark.asyncio
    async def test_never_persists_ticket(self):
        store = OneSlotStore()
        _stored_context(store, session_token="REAL_TOKEN", domain="auth0.local")
        client = _make_client(anonymous_store=store)
        before = store.slot
        fake_http = _FakeAsyncClient([_fake_response(200, _TRANSFER_OK)])
        with patch("httpx.AsyncClient", fake_http):
            await client.exchange_transfer_token_for_injection("auth0.local")
        assert store.slot is before  # the ticket was never written to the store

    @pytest.mark.asyncio
    async def test_returns_none_on_store_exception(self):
        store = AsyncMock()
        store.get = AsyncMock(side_effect=RuntimeError("store unavailable"))
        client = _make_client(anonymous_store=store)
        assert await client.exchange_transfer_token_for_injection("auth0.local") is None

    @pytest.mark.asyncio
    async def test_forwards_configured_headers(self):
        """The exchange goes through _get_http_client, so telemetry/config headers are attached."""
        store = OneSlotStore()
        _stored_context(store, domain="auth0.local")
        captured = {}

        class _Cap:
            def __call__(self, *a, **k):
                captured.update(k.get("headers", {}))
                return self

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def post(self, *a, **k):
                return _fake_response(200, _TRANSFER_OK)

        client = _make_client(anonymous_store=store, headers={"Auth0-Client": "abc"})
        with patch("httpx.AsyncClient", _Cap()):
            await client.exchange_transfer_token_for_injection("auth0.local")
        assert captured.get("Auth0-Client") == "abc"


# ── _end_session_if_active (end anon session on authenticated logout) ────────────

class TestEndSessionIfActive:
    @pytest.mark.asyncio
    async def test_no_store_is_noop(self):
        client = _make_client(anonymous_store=None)
        with patch("httpx.AsyncClient") as mock_http:
            await client._end_session_if_active()
            mock_http.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_session_makes_no_remote_call(self):
        store = OneSlotStore()
        client = _make_client(anonymous_store=store)
        with patch("httpx.AsyncClient") as mock_http:
            await client._end_session_if_active()
            mock_http.assert_not_called()

    @pytest.mark.asyncio
    async def test_active_session_clears_local_without_remote_call(self):
        store = OneSlotStore()
        _stored_context(store, domain="auth0.local")
        client = _make_client(anonymous_store=store)
        with patch("httpx.AsyncClient") as mock_http:
            await client._end_session_if_active()
            mock_http.assert_not_called()
        assert store.slot is None

    @pytest.mark.asyncio
    async def test_store_exception_is_swallowed(self):
        store = AsyncMock()
        store.get = AsyncMock(side_effect=RuntimeError("store unavailable"))
        client = _make_client(anonymous_store=store)
        await client._end_session_if_active()  # must not raise


# ── get_session ───────────────────────────────────────────────────────────────

class TestGetSession:
    @pytest.mark.asyncio
    async def test_returns_none_when_no_store_configured(self):
        client = _make_client()
        result = await client.get_session()
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_when_no_session_stored(self):
        store = OneSlotStore()
        client = _make_client(anonymous_store=store)
        result = await client.get_session()
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_session_data_with_identity_fields(self):
        store = OneSlotStore()
        _stored_context(store, sub="anon@test-uuid", domain="auth0.local")
        client = _make_client(anonymous_store=store)
        result = await client.get_session()
        assert isinstance(result, AnonymousSessionData)
        assert result.sub == "anon@test-uuid"
        assert result.domain == "auth0.local"

    @pytest.mark.asyncio
    async def test_does_not_include_session_token(self):
        store = OneSlotStore()
        _stored_context(store)
        client = _make_client(anonymous_store=store)
        result = await client.get_session()
        assert not hasattr(result, "session_token") or not isinstance(getattr(result, "session_token", None), str)

    @pytest.mark.asyncio
    async def test_makes_no_http_call(self):
        store = OneSlotStore()
        _stored_context(store)
        client = _make_client(anonymous_store=store)
        with patch("httpx.AsyncClient") as mock_http:
            await client.get_session()
            mock_http.assert_not_called()

    @pytest.mark.asyncio
    async def test_returns_none_for_corrupt_session(self):
        store = OneSlotStore()
        store.slot = (ANON_IDENTIFIER, {"context": "not-valid-jwe"})
        client = _make_client(anonymous_store=store)
        result = await client.get_session()
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_when_store_raises(self):
        store = AsyncMock()
        store.get = AsyncMock(side_effect=RuntimeError("store down"))
        client = _make_client(anonymous_store=store)
        result = await client.get_session()
        assert result is None

    @pytest.mark.asyncio
    async def test_domain_mismatch_in_resolver_mode_returns_none(self):
        store = OneSlotStore()
        _stored_context(store, domain="tenant-a.auth0.local")
        resolver = AsyncMock(return_value="tenant-b.auth0.local")
        client = AnonymousClient(
            domain=resolver, client_id=CLIENT_ID, client_secret=CLIENT_SECRET,
            secret=SECRET, anonymous_store=store,
        )
        result = await client.get_session()
        assert result is None

    @pytest.mark.asyncio
    async def test_domain_match_in_resolver_mode_returns_session(self):
        store = OneSlotStore()
        _stored_context(store, domain="tenant-a.auth0.local")
        resolver = AsyncMock(return_value="tenant-a.auth0.local")
        client = AnonymousClient(
            domain=resolver, client_id=CLIENT_ID, client_secret=CLIENT_SECRET,
            secret=SECRET, anonymous_store=store,
        )
        result = await client.get_session()
        assert result is not None
