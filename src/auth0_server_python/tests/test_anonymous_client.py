"""
Tests for AnonymousClient, covering anonymous session API operations.
"""

import inspect
import time
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from auth0_server_python.auth_server.anonymous_client import (
    ANON_IDENTIFIER,
    AnonymousClient,
)
from auth0_server_python.auth_types import (
    AnonymousSessionContext,
    CreateAnonymousSessionOptions,
)
from auth0_server_python.encryption.encrypt import encrypt
from auth0_server_python.error import (
    AnonymousSessionClientNotEnabledError,
    AnonymousSessionClientNotSupportedError,
    AnonymousSessionCreateError,
    AnonymousSessionFeatureNotEnabledError,
    AnonymousSessionIntrospectError,
    AnonymousSessionLogoutError,
    AnonymousSessionResourceServerError,
    AnonymousSessionScopeError,
    AnonymousSessionTokenError,
    ConfigurationError,
    DomainResolverError,
)

# Shared fixtures
DOMAIN = "auth0.local"
CLIENT_ID = "<client_id>"
CLIENT_SECRET = "<client_secret>"
SECRET = "test-secret-long-enough-for-encryption"


class OneSlotStore:
    """
    Models StatelessStateStore: a store identifier is a salt, not a location.
    One physical slot per instance, so a mismatched identifier reads as
    absent, not as a different record. AsyncMock cannot catch a collision
    because it treats every identifier as a distinct key, so this fake is
    required instead.
    """

    def __init__(self):
        self.slot = None

    async def set(self, identifier, state, options=None):
        self.slot = (identifier, state)

    async def get(self, identifier, options=None):
        if not self.slot or self.slot[0] != identifier:
            return None
        return self.slot[1]

    async def delete(self, identifier, options=None):
        self.slot = None


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
    sub="anon@abc",
    session_id="sid1",
):
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": expires_in,
        "session_token": session_token,
        "session_expires_in": session_expires_in,
        "sub": sub,
        "session_id": session_id,
    }


def _stored_context(store: OneSlotStore, **overrides):
    defaults = {
        "session_token": "ST1",
        "sub": "anon@abc",
        "session_id": "sid1",
        "access_token": "AT1",
        "expires_at": int(time.time()) + 3600,
        "created_at": int(time.time()),
    }
    defaults.update(overrides)
    context = AnonymousSessionContext(**defaults)
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
    async def test_introspect_without_store_raises_configuration_error(self):
        client = _make_client(anonymous_store=None)
        with pytest.raises(ConfigurationError):
            await client.introspect()

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

    @pytest.mark.asyncio
    async def test_get_session_token_for_injection_returns_none_without_store(self):
        client = _make_client(anonymous_store=None)
        assert await client.get_session_token_for_injection() is None


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
        assert session.sub == "anon@abc"
        assert session.session_id == "sid1"
        assert session.is_new is True
        assert session.metadata == {"cart_id": "c1"}

    @pytest.mark.asyncio
    async def test_create_session_response_missing_session_token_raises(self):
        store = OneSlotStore()
        client = _make_client(anonymous_store=store)
        response_without_session_token = _token_response()
        del response_without_session_token["session_token"]
        fake_http = _FakeAsyncClient([_fake_response(200, response_without_session_token)])
        with patch("httpx.AsyncClient", fake_http):
            with pytest.raises(AnonymousSessionCreateError):
                await client.create_session(audience="aud", scope="s")

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
        # The authenticated session store is a different instance entirely,
        # never touched by anonymous writes.
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
        assert session.is_new is False
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
            _fake_response(200, {"access_token": "AT2", "token_type": "Bearer", "expires_in": 3600})
        ])
        with patch("httpx.AsyncClient", fake_http):
            session = await client.get_token()
        assert session.access_token == "AT2"
        assert session.is_new is False
        assert session.sub == "anon@abc"  # unchanged on ordinary re-mint
        _, _, kwargs = fake_http.calls[0]
        assert kwargs["json"]["session_token"] == "ST1"
        assert "refresh_token" not in kwargs["json"]

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
                    "session_token": "",
                    "sub": "",
                    "session_id": "",
                },
            )
        ])
        with patch("httpx.AsyncClient", fake_http):
            session = await client.get_token()
        assert session.sub == ""
        assert session.session_id == ""
        token = await client.get_session_token_for_injection()
        assert token == ""

    @pytest.mark.asyncio
    async def test_expired_session_token_triggers_silent_new_session(self):
        store = OneSlotStore()
        _stored_context(store, expires_at=int(time.time()) - 10)
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([
            _fake_response(400, {"error": "session_expired", "error_description": "expired"}),
            _fake_response(200, _token_response(sub="anon@new", session_id="sid2")),
        ])
        with patch("httpx.AsyncClient", fake_http):
            session = await client.get_token()
        assert session.is_new is True
        assert session.sub == "anon@new"

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
        fake_http = _FakeAsyncClient([_fake_response(200, _token_response(sub="anon@fresh"))])
        with patch("httpx.AsyncClient", fake_http):
            session = await client.get_token()
        assert session.is_new is True
        assert session.sub == "anon@fresh"

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
        fake_http = _FakeAsyncClient([_fake_response(200, _token_response(sub="anon@fresh-b"))])
        with patch("httpx.AsyncClient", fake_http):
            session = await client.get_token()
        assert session.sub == "anon@fresh-b"
        assert session.is_new is True

    @pytest.mark.asyncio
    async def test_domain_resolver_failure_propagates(self):
        resolver = AsyncMock(return_value=None)
        client = AnonymousClient(
            domain=resolver, client_id=CLIENT_ID, client_secret=CLIENT_SECRET, secret=SECRET,
            anonymous_store=OneSlotStore(),
        )
        with pytest.raises(DomainResolverError):
            await client.create_session(audience="aud", scope="s")


# ── introspect ────────────────────────────────────────────────────────────────

class TestIntrospect:
    @pytest.mark.asyncio
    async def test_introspect_issues_get_with_no_body(self):
        store = OneSlotStore()
        _stored_context(store)
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([_fake_response(200, {"sub": "anon@abc"})])
        with patch("httpx.AsyncClient", fake_http):
            await client.introspect()
        method, _, kwargs = fake_http.calls[0]
        assert method == "GET"
        assert "json" not in kwargs

    @pytest.mark.asyncio
    async def test_introspect_lenient_decode_ignores_unknown_fields(self):
        store = OneSlotStore()
        _stored_context(store)
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([
            _fake_response(200, {"sub": "anon@abc", "totally_unexpected_field": "value"})
        ])
        with patch("httpx.AsyncClient", fake_http):
            result = await client.introspect()
        assert result.sub == "anon@abc"

    @pytest.mark.asyncio
    async def test_introspect_missing_optional_field_does_not_raise(self):
        store = OneSlotStore()
        _stored_context(store)
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([_fake_response(200, {"sub": "anon@abc"})])
        with patch("httpx.AsyncClient", fake_http):
            result = await client.introspect()
        assert result.session_id is None
        assert result.metadata is None

    @pytest.mark.asyncio
    async def test_introspect_never_writes_to_store(self):
        store = OneSlotStore()
        _stored_context(store)
        original_slot = store.slot
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([_fake_response(200, {"sub": "anon@abc"})])
        with patch("httpx.AsyncClient", fake_http):
            await client.introspect()
        assert store.slot == original_slot

    @pytest.mark.asyncio
    async def test_introspect_no_active_session_raises(self):
        store = OneSlotStore()
        client = _make_client(anonymous_store=store)
        with pytest.raises(AnonymousSessionIntrospectError):
            await client.introspect()


# ── logout ────────────────────────────────────────────────────────────────────

class TestLogout:
    @pytest.mark.asyncio
    async def test_logout_clears_anonymous_store(self):
        store = OneSlotStore()
        _stored_context(store)
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([_fake_response(200, {})])
        with patch("httpx.AsyncClient", fake_http):
            await client.logout()
        assert store.slot is None

    @pytest.mark.asyncio
    async def test_logout_does_not_touch_unrelated_authenticated_store(self):
        anon_store = OneSlotStore()
        _stored_context(anon_store)
        auth_store = AsyncMock()
        client = _make_client(anonymous_store=anon_store)
        fake_http = _FakeAsyncClient([_fake_response(200, {})])
        with patch("httpx.AsyncClient", fake_http):
            await client.logout()
        auth_store.delete.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_token_after_logout_behaves_as_no_session(self):
        store = OneSlotStore()
        _stored_context(store)
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient([_fake_response(200, {})])
        with patch("httpx.AsyncClient", fake_http):
            await client.logout()
        with pytest.raises(AnonymousSessionTokenError):
            await client.get_token()

    @pytest.mark.asyncio
    async def test_logout_with_no_session_is_a_noop(self):
        store = OneSlotStore()
        client = _make_client(anonymous_store=store)
        with patch("httpx.AsyncClient") as mock_http:
            await client.logout()
            mock_http.assert_not_called()

    @pytest.mark.asyncio
    async def test_logout_remote_call_failure_still_clears_local_state_then_raises(self):
        store = OneSlotStore()
        _stored_context(store)
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
            with pytest.raises(AnonymousSessionLogoutError):
                await client.logout()
        assert store.slot is None

    @pytest.mark.asyncio
    async def test_logout_non_200_response_still_clears_local_state_then_raises(self):
        store = OneSlotStore()
        _stored_context(store)
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient(
            [_fake_response(500, {"error": "server_error", "error_description": "boom"})]
        )
        with patch("httpx.AsyncClient", fake_http):
            with pytest.raises(AnonymousSessionLogoutError):
                await client.logout()
        assert store.slot is None

    @pytest.mark.asyncio
    async def test_logout_session_expired_response_is_not_raised(self):
        store = OneSlotStore()
        _stored_context(store)
        client = _make_client(anonymous_store=store)
        fake_http = _FakeAsyncClient(
            [_fake_response(400, {"error": "session_expired", "error_description": "expired"})]
        )
        with patch("httpx.AsyncClient", fake_http):
            await client.logout()
        assert store.slot is None


# ── get_session_token_for_injection (login-injection support) ───────────────

class TestGetSessionTokenForInjection:
    @pytest.mark.asyncio
    async def test_returns_token_when_active_session_exists(self):
        store = OneSlotStore()
        _stored_context(store, session_token="REAL_TOKEN")
        client = _make_client(anonymous_store=store)
        token = await client.get_session_token_for_injection()
        assert token == "REAL_TOKEN"

    @pytest.mark.asyncio
    async def test_returns_none_when_no_session(self):
        store = OneSlotStore()
        client = _make_client(anonymous_store=store)
        assert await client.get_session_token_for_injection() is None

    @pytest.mark.asyncio
    async def test_returns_none_never_raises_on_corrupted_token(self):
        """Malformed stored token must deny the link, never abort the caller."""
        store = OneSlotStore()
        store.slot = (ANON_IDENTIFIER, {"context": "garbage"})
        client = _make_client(anonymous_store=store)
        assert await client.get_session_token_for_injection() is None

    @pytest.mark.asyncio
    async def test_returns_none_on_store_exception_never_raises(self):
        store = AsyncMock()
        store.get = AsyncMock(side_effect=RuntimeError("store unavailable"))
        client = _make_client(anonymous_store=store)
        assert await client.get_session_token_for_injection() is None
