"""
Tests for PasswordlessClient — embedded passwordless (OTP + magic link).
"""

from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import ValidationError

from auth0_server_python.auth_server.passwordless_client import (
    PASSWORDLESS_OTP_GRANT_TYPE,
    PasswordlessClient,
)
from auth0_server_python.auth_server.server_client import ServerClient
from auth0_server_python.auth_types import (
    StartPasswordlessEmailOptions,
    StartPasswordlessSmsOptions,
    TransactionData,
    VerifyPasswordlessOtpOptions,
)
from auth0_server_python.error import (
    InvalidArgumentError,
    IssuerValidationError,
    MissingRequiredArgumentError,
    PasswordlessStartError,
    PasswordlessVerifyError,
    SessionExpiredError,
)

DOMAIN = "tenant.auth0.com"
CLIENT_ID = "test_client"
CLIENT_SECRET = "test_secret"
SECRET = "test_secret_key_32_chars_long!!!"
REDIRECT_URI = "https://app.example.com/auth/callback"
ISSUER = "https://tenant.auth0.com/"
METADATA = {"token_endpoint": f"https://{DOMAIN}/oauth/token", "issuer": ISSUER}


def _make_client(**overrides) -> ServerClient:
    kwargs = {
        "domain": DOMAIN,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "secret": SECRET,
        "redirect_uri": REDIRECT_URI,
        "transaction_store": AsyncMock(),
        "state_store": AsyncMock(),
    }
    kwargs.update(overrides)
    return ServerClient(**kwargs)


def _mock_http(client: ServerClient, status_code: int, json_body):
    """Patch client._get_http_client so post() returns the given response."""
    response = MagicMock(status_code=status_code)
    response.json = MagicMock(return_value=json_body)
    http = AsyncMock()
    http.post = AsyncMock(return_value=response)
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=http)
    ctx.__aexit__ = AsyncMock(return_value=False)
    client._get_http_client = MagicMock(return_value=ctx)
    return http


# ── Wiring ───────────────────────────────────────────────────────────────────


class TestWiring:
    def test_passwordless_property(self):
        client = _make_client()
        assert isinstance(client.passwordless, PasswordlessClient)
        assert client.passwordless._client is client


# ── start(): OTP ───────────────────────────────────────────────────────────


class TestStartOtp:
    @pytest.mark.asyncio
    async def test_email_otp_start(self):
        client = _make_client()
        http = _mock_http(client, 200, {"_id": "req_123"})

        result = await client.passwordless.start(
            StartPasswordlessEmailOptions(email="user@example.com", send="code")
        )

        body = http.post.call_args.kwargs["json"]
        assert body["connection"] == "email"
        assert body["email"] == "user@example.com"
        assert body["send"] == "code"
        assert body["client_id"] == CLIENT_ID
        assert body["client_secret"] == CLIENT_SECRET
        # OTP flow does not create a transaction.
        client._transaction_store.set.assert_not_awaited()
        # Auth0 returns the request id as `_id`; the model aliases it to `.id`.
        assert result.id == "req_123"

    @pytest.mark.asyncio
    async def test_sms_otp_start(self):
        client = _make_client()
        http = _mock_http(client, 200, {})

        await client.passwordless.start(StartPasswordlessSmsOptions(phone_number="+14155550100"))

        body = http.post.call_args.kwargs["json"]
        assert body["connection"] == "sms"
        assert body["phone_number"] == "+14155550100"
        assert "send" not in body

    @pytest.mark.asyncio
    async def test_language_sets_header(self):
        client = _make_client()
        http = _mock_http(client, 200, {})

        await client.passwordless.start(
            StartPasswordlessEmailOptions(email="user@example.com", send="code", language="fr")
        )

        headers = http.post.call_args.kwargs["headers"]
        assert headers["x-request-language"] == "fr"

    @pytest.mark.asyncio
    async def test_start_error_maps_to_typed_exception(self):
        client = _make_client()
        _mock_http(
            client,
            400,
            {"error": "bad.connection", "error_description": "Connection disabled"},
        )

        with pytest.raises(PasswordlessStartError) as exc:
            await client.passwordless.start(
                StartPasswordlessEmailOptions(email="user@example.com", send="code")
            )
        assert exc.value.code == "bad.connection"
        assert exc.value.error == "bad.connection"
        assert exc.value.error_description == "Connection disabled"

    @pytest.mark.asyncio
    async def test_sms_e164_rejected_at_model(self):
        # Validation happens at model construction, before any network call.
        with pytest.raises(ValidationError):
            StartPasswordlessSmsOptions(phone_number="4155550100")


# ── start(): Magic link ──────────────────────────────────────────────────────


class TestStartMagicLink:
    @pytest.mark.asyncio
    async def test_magic_link_sets_sdk_owned_params_and_persists_tx(self):
        client = _make_client()
        http = _mock_http(client, 200, {})

        await client.passwordless.start(
            StartPasswordlessEmailOptions(email="user@example.com", send="link"),
            store_options={},
        )

        body = http.post.call_args.kwargs["json"]
        ap = body["authParams"]
        assert ap["redirect_uri"] == REDIRECT_URI
        assert ap["response_type"] == "code"
        assert "state" in ap and len(ap["state"]) >= 16
        assert ap["scope"]  # default scope applied

        # Transaction persisted, single-use + bounded TTL, no PKCE verifier.
        client._transaction_store.set.assert_awaited_once()
        set_call = client._transaction_store.set.await_args
        tx_key = set_call.args[0]
        tx_data = set_call.args[1]
        assert tx_key == f"{client._transaction_identifier}:{ap['state']}"
        assert set_call.kwargs["remove_if_expires"] is True
        assert tx_data.code_verifier is None
        assert tx_data.redirect_uri == REDIRECT_URI

    @pytest.mark.asyncio
    async def test_magic_link_requires_store_options(self):
        # No store_options -> transaction cookie can't be persisted -> fail loudly.
        client = _make_client()
        _mock_http(client, 200, {})

        with pytest.raises(MissingRequiredArgumentError):
            await client.passwordless.start(
                StartPasswordlessEmailOptions(email="user@example.com", send="link"),
                store_options=None,
            )
        client._transaction_store.set.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_magic_link_requires_redirect_uri(self):
        client = _make_client(redirect_uri=None)
        _mock_http(client, 200, {})

        with pytest.raises(MissingRequiredArgumentError):
            await client.passwordless.start(
                StartPasswordlessEmailOptions(email="user@example.com", send="link")
            )

    @pytest.mark.asyncio
    async def test_caller_cannot_override_reserved_param(self):
        client = _make_client()
        _mock_http(client, 200, {})

        with pytest.raises(InvalidArgumentError):
            await client.passwordless.start(
                StartPasswordlessEmailOptions(
                    email="user@example.com",
                    send="link",
                    auth_params={"redirect_uri": "https://evil.example.com/steal"},
                )
            )
        # No transaction written when the override is rejected.
        client._transaction_store.set.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_caller_safe_param_passed_through(self):
        client = _make_client()
        http = _mock_http(client, 200, {})

        await client.passwordless.start(
            StartPasswordlessEmailOptions(
                email="user@example.com",
                send="link",
                auth_params={"login_hint": "user@example.com"},
            ),
            store_options={},
        )
        ap = http.post.call_args.kwargs["json"]["authParams"]
        assert ap["login_hint"] == "user@example.com"
        assert ap["redirect_uri"] == REDIRECT_URI  # still SDK-owned

    @pytest.mark.asyncio
    async def test_caller_unrecognized_param_rejected(self):
        # Allowlist posture: a param outside the allowlist is rejected, not
        # silently forwarded, so a future authorize param can't slip through.
        client = _make_client()
        _mock_http(client, 200, {})

        with pytest.raises(InvalidArgumentError):
            await client.passwordless.start(
                StartPasswordlessEmailOptions(
                    email="user@example.com",
                    send="link",
                    auth_params={"response_mode": "fragment"},
                )
            )
        client._transaction_store.set.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_connection_scope_not_allowed(self):
        # connection_scope is a federated-connection param with no meaning for
        # email/SMS passwordless; it is not in the allowlist and is rejected.
        client = _make_client()
        _mock_http(client, 200, {})

        with pytest.raises(InvalidArgumentError):
            await client.passwordless.start(
                StartPasswordlessEmailOptions(
                    email="user@example.com",
                    send="link",
                    auth_params={"connection_scope": "read:foo"},
                )
            )
        client._transaction_store.set.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_client_ip_forwarded_on_start(self):
        client = _make_client()
        http = _mock_http(client, 200, {})

        await client.passwordless.start(
            StartPasswordlessEmailOptions(
                email="user@example.com", send="code", client_ip="203.0.113.7"
            )
        )
        headers = http.post.call_args.kwargs["headers"]
        assert headers["auth0-forwarded-for"] == "203.0.113.7"


# ── Magic link callback completion (complete_interactive_login) ──────────────


class TestMagicLinkCallback:
    @pytest.mark.asyncio
    async def test_magic_link_callback_exchanges_code_without_pkce(self, mocker):
        # Magic link is a plain auth-code exchange: lock that code_verifier=None
        # reaches fetch_token (authlib drops the falsy field) so a forced verifier
        # — which Auth0 would reject — is caught.
        client = _make_client()
        client._transaction_store.get.return_value = TransactionData(
            code_verifier=None,
            redirect_uri=REDIRECT_URI,
            domain=DOMAIN,
        )

        mocker.patch.object(client, "_get_oidc_metadata_cached", return_value=METADATA)
        mocker.patch.object(client._oauth, "metadata", METADATA)
        mocker.patch.object(
            client,
            "_get_jwks_cached",
            return_value={"keys": [{"kty": "RSA", "kid": "k1"}]},
        )
        mocker.patch.object(
            client,
            "_verify_and_decode_jwt",
            return_value={"iss": ISSUER, "sub": "auth0|1", "sid": "SID-1", "iat": 1_000},
        )
        fetch_token = AsyncMock(
            return_value={
                "access_token": "at",
                "id_token": "idt",
                "expires_in": 3600,
                "scope": "openid",
            }
        )
        mocker.patch.object(client._oauth, "fetch_token", fetch_token)

        result = await client.complete_interactive_login(
            f"{REDIRECT_URI}?code=AUTHCODE&state=STATE-1"
        )

        assert fetch_token.await_args.kwargs["code_verifier"] is None
        assert fetch_token.await_args.kwargs["code"] == "AUTHCODE"

        # Session established; transaction consumed (single-use).
        client._state_store.set.assert_awaited_once()
        client._transaction_store.delete.assert_awaited_once()
        assert result["state_data"]["internal"]["sid"] == "SID-1"


# ── verify() ─────────────────────────────────────────────────────────────────


class TestVerify:
    def _patch_verify_deps(self, client, mocker, claims):
        mocker.patch.object(client, "_get_oidc_metadata_cached", return_value=METADATA)
        mocker.patch.object(
            client,
            "_get_jwks_cached",
            return_value={"keys": [{"kty": "RSA", "kid": "k1"}]},
        )
        mocker.patch.object(client, "_verify_and_decode_jwt", return_value=claims)

    @pytest.mark.asyncio
    async def test_email_otp_verify_creates_session(self, mocker):
        client = _make_client()
        claims = {"iss": ISSUER, "sub": "auth0|1", "sid": "SID-123", "iat": 1_000}
        self._patch_verify_deps(client, mocker, claims)
        http = _mock_http(
            client,
            200,
            {"access_token": "at", "id_token": "idt", "expires_in": 3600, "scope": "openid"},
        )

        result = await client.passwordless.verify(
            VerifyPasswordlessOtpOptions(
                connection="email", email="user@example.com", verification_code="123456"
            )
        )

        # Correct grant + params on the token call.
        data = http.post.call_args.kwargs["data"]
        assert data["grant_type"] == PASSWORDLESS_OTP_GRANT_TYPE
        assert data["realm"] == "email"
        assert data["username"] == "user@example.com"
        assert data["otp"] == "123456"

        # Session persisted, sid taken from the ID token claim (not random).
        client._state_store.set.assert_awaited_once()
        assert "state_data" in result
        assert result["state_data"]["internal"]["sid"] == "SID-123"

    @pytest.mark.asyncio
    async def test_sms_otp_verify_username_is_phone(self, mocker):
        client = _make_client()
        claims = {"iss": ISSUER, "sub": "auth0|2", "sid": "SID-9", "iat": 1_000}
        self._patch_verify_deps(client, mocker, claims)
        http = _mock_http(
            client, 200, {"access_token": "at", "id_token": "idt", "expires_in": 3600}
        )

        await client.passwordless.verify(
            VerifyPasswordlessOtpOptions(
                connection="sms", phone_number="+14155550100", verification_code="000111"
            )
        )
        data = http.post.call_args.kwargs["data"]
        assert data["realm"] == "sms"
        assert data["username"] == "+14155550100"
        # SMS has no email claim to satisfy, so the default scope omits `email`.
        assert data["scope"] == "openid profile"

    @pytest.mark.asyncio
    async def test_email_verify_default_scope_includes_email(self, mocker):
        client = _make_client()
        claims = {"iss": ISSUER, "sub": "auth0|1", "sid": "s", "iat": 1_000}
        self._patch_verify_deps(client, mocker, claims)
        http = _mock_http(
            client, 200, {"access_token": "at", "id_token": "idt", "expires_in": 3600}
        )

        await client.passwordless.verify(
            VerifyPasswordlessOtpOptions(
                connection="email", email="user@example.com", verification_code="123456"
            )
        )
        assert http.post.call_args.kwargs["data"]["scope"] == "openid profile email"

    @pytest.mark.asyncio
    async def test_client_ip_forwarded_on_verify(self, mocker):
        client = _make_client()
        claims = {"iss": ISSUER, "sub": "auth0|1", "sid": "s", "iat": 1_000}
        self._patch_verify_deps(client, mocker, claims)
        http = _mock_http(
            client, 200, {"access_token": "at", "id_token": "idt", "expires_in": 3600}
        )

        await client.passwordless.verify(
            VerifyPasswordlessOtpOptions(
                connection="email",
                email="user@example.com",
                verification_code="123456",
                client_ip="203.0.113.7",
            )
        )
        headers = http.post.call_args.kwargs["headers"]
        assert headers["auth0-forwarded-for"] == "203.0.113.7"

    @pytest.mark.asyncio
    async def test_verify_invalid_otp_maps_to_typed_error(self, mocker):
        client = _make_client()
        mocker.patch.object(client, "_get_oidc_metadata_cached", return_value=METADATA)
        _mock_http(
            client,
            403,
            {"error": "invalid_grant", "error_description": "Wrong code"},
        )

        with pytest.raises(PasswordlessVerifyError) as exc:
            await client.passwordless.verify(
                VerifyPasswordlessOtpOptions(
                    connection="email", email="user@example.com", verification_code="000000"
                )
            )
        assert exc.value.code == "invalid_grant"
        client._state_store.set.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_verify_issuer_mismatch_rejected(self, mocker):
        client = _make_client()
        claims = {"iss": "https://attacker.evil.com/", "sub": "x", "sid": "s", "iat": 1_000}
        self._patch_verify_deps(client, mocker, claims)
        _mock_http(client, 200, {"access_token": "at", "id_token": "idt", "expires_in": 3600})

        with pytest.raises(IssuerValidationError):
            await client.passwordless.verify(
                VerifyPasswordlessOtpOptions(
                    connection="email", email="user@example.com", verification_code="123456"
                )
            )
        client._state_store.set.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_verify_missing_id_token_rejected(self, mocker):
        client = _make_client()
        mocker.patch.object(client, "_get_oidc_metadata_cached", return_value=METADATA)
        _mock_http(client, 200, {"access_token": "at", "expires_in": 3600})

        with pytest.raises(PasswordlessVerifyError):
            await client.passwordless.verify(
                VerifyPasswordlessOtpOptions(
                    connection="email", email="user@example.com", verification_code="123456"
                )
            )

    @pytest.mark.asyncio
    async def test_verify_discovery_failure_mapped(self, mocker):
        client = _make_client()
        mocker.patch.object(client, "_get_oidc_metadata_cached", side_effect=Exception("boom"))

        with pytest.raises(PasswordlessVerifyError) as exc:
            await client.passwordless.verify(
                VerifyPasswordlessOtpOptions(
                    connection="email", email="user@example.com", verification_code="123456"
                )
            )
        assert exc.value.code == "discovery_error"

    @pytest.mark.asyncio
    async def test_verify_ceiling_in_past_rejected(self, mocker):
        client = _make_client()
        # session_expiry well before iat -> ceiling already past.
        claims = {
            "iss": ISSUER,
            "sub": "x",
            "sid": "s",
            "iat": 2_000_000_000,
            "session_expiry": 1_000,
        }
        self._patch_verify_deps(client, mocker, claims)
        _mock_http(client, 200, {"access_token": "at", "id_token": "idt", "expires_in": 3600})

        with pytest.raises(SessionExpiredError):
            await client.passwordless.verify(
                VerifyPasswordlessOtpOptions(
                    connection="email", email="user@example.com", verification_code="123456"
                )
            )
        client._state_store.set.assert_not_awaited()
