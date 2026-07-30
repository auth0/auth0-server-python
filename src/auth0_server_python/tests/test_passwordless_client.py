"""
Tests for PasswordlessClient — embedded passwordless (OTP + magic link).
"""

from unittest.mock import AsyncMock, MagicMock

import pytest
from jwcrypto import jwk
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
    MfaRequiredError,
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

    @pytest.mark.asyncio
    async def test_caller_scope_forwarded_on_magic_link(self):
        client = _make_client()
        http = _mock_http(client, 200, {})

        await client.passwordless.start(
            StartPasswordlessEmailOptions(
                email="user@example.com",
                send="link",
                auth_params={"scope": "openid profile email offline_access read:orders"},
            ),
            store_options={},
        )
        ap = http.post.call_args.kwargs["json"]["authParams"]
        assert ap["scope"] == "openid profile email offline_access read:orders"

    @pytest.mark.asyncio
    async def test_magic_link_default_scope_applies_when_caller_omits_it(self):
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
        assert ap["scope"] == "openid profile email"

    @pytest.mark.asyncio
    async def test_magic_link_organization_reaches_auth_params_and_transaction(self):
        client = _make_client()
        http = _mock_http(client, 200, {})

        await client.passwordless.start(
            StartPasswordlessEmailOptions(
                email="user@example.com",
                send="link",
                organization="org_abc123",
            ),
            store_options={},
        )
        ap = http.post.call_args.kwargs["json"]["authParams"]
        assert ap["organization"] == "org_abc123"

        tx_data = client._transaction_store.set.await_args.args[1]
        assert tx_data.organization == "org_abc123"


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

        with pytest.raises(PasswordlessVerifyError) as exc:
            await client.passwordless.verify(
                VerifyPasswordlessOtpOptions(
                    connection="email", email="user@example.com", verification_code="123456"
                )
            )
        assert exc.value.code == "invalid_issuer"
        assert isinstance(exc.value.cause, IssuerValidationError)
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

    @pytest.mark.asyncio
    async def test_verify_rate_limited_maps_to_too_many_requests(self, mocker):
        client = _make_client()
        mocker.patch.object(client, "_get_oidc_metadata_cached", return_value=METADATA)
        _mock_http(client, 429, {})

        with pytest.raises(PasswordlessVerifyError) as exc:
            await client.passwordless.verify(
                VerifyPasswordlessOtpOptions(
                    connection="email", email="user@example.com", verification_code="123456"
                )
            )
        assert exc.value.code == "too_many_requests"
        client._state_store.set.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_verify_mfa_required_raises_typed_error(self, mocker):
        client = _make_client()
        mocker.patch.object(client, "_get_oidc_metadata_cached", return_value=METADATA)
        _mock_http(
            client,
            403,
            {
                "error": "mfa_required",
                "error_description": "Additional factor required",
                "mfa_token": "raw_server_mfa_token",
            },
        )

        with pytest.raises(MfaRequiredError) as exc:
            await client.passwordless.verify(
                VerifyPasswordlessOtpOptions(
                    connection="email", email="user@example.com", verification_code="123456"
                )
            )
        # Token is re-encrypted by the SDK, never passed through raw.
        assert exc.value.mfa_token is not None
        assert exc.value.mfa_token != "raw_server_mfa_token"
        decrypted = client._mfa_client.decrypt_mfa_token(exc.value.mfa_token)
        assert decrypted.mfa_token == "raw_server_mfa_token"
        client._state_store.set.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_verify_mfa_required_without_token_falls_through(self, mocker):
        # Third-party-strict / flex-commands-with-FF-off: 403 mfa_required with
        # no mfa_token. Must fall through to the generic typed error, not hang
        # or raise an unrelated exception.
        client = _make_client()
        mocker.patch.object(client, "_get_oidc_metadata_cached", return_value=METADATA)
        _mock_http(
            client,
            403,
            {"error": "mfa_required", "error_description": "MFA required"},
        )

        with pytest.raises(PasswordlessVerifyError) as exc:
            await client.passwordless.verify(
                VerifyPasswordlessOtpOptions(
                    connection="email", email="user@example.com", verification_code="123456"
                )
            )
        assert exc.value.code == "mfa_required"
        client._state_store.set.assert_not_awaited()


# ── verify(): DPoP ───────────────────────────────────────────────────────────


class TestVerifyDpop:
    def _patch_verify_deps(self, client, mocker, claims):
        mocker.patch.object(client, "_get_oidc_metadata_cached", return_value=METADATA)
        mocker.patch.object(
            client,
            "_get_jwks_cached",
            return_value={"keys": [{"kty": "RSA", "kid": "k1"}]},
        )
        mocker.patch.object(client, "_verify_and_decode_jwt", return_value=claims)

    @pytest.mark.asyncio
    async def test_verify_with_dpop_key_sends_proof_and_accepts_dpop_token(self, mocker):
        client = _make_client()
        claims = {"iss": ISSUER, "sub": "auth0|1", "sid": "SID-1", "iat": 1_000}
        self._patch_verify_deps(client, mocker, claims)
        dpop_key = jwk.JWK.generate(kty="EC", crv="P-256")
        http = _mock_http(
            client,
            200,
            {
                "access_token": "bound_at",
                "token_type": "DPoP",
                "id_token": "idt",
                "expires_in": 3600,
            },
        )
        http.post.return_value.headers = {}

        await client.passwordless.verify(
            VerifyPasswordlessOtpOptions(
                connection="email", email="user@example.com", verification_code="123456"
            ),
            dpop_key=dpop_key,
        )
        headers = http.post.call_args.kwargs["headers"]
        assert "DPoP" in headers

    @pytest.mark.asyncio
    async def test_verify_dpop_nonce_retry(self, mocker):
        """RFC 9449 §8.2: a DPoP-Nonce challenge triggers exactly one retry with the nonce."""
        client = _make_client()
        claims = {"iss": ISSUER, "sub": "auth0|1", "sid": "SID-1", "iat": 1_000}
        self._patch_verify_deps(client, mocker, claims)
        dpop_key = jwk.JWK.generate(kty="EC", crv="P-256")

        challenge = MagicMock(status_code=400)
        challenge.headers = {"DPoP-Nonce": "server-nonce-123"}
        challenge.json = MagicMock(return_value={"error": "use_dpop_nonce"})

        success = MagicMock(status_code=200)
        success.headers = {}
        success.json = MagicMock(
            return_value={
                "access_token": "bound_at",
                "token_type": "DPoP",
                "id_token": "idt",
                "expires_in": 3600,
            }
        )

        proofs = []

        async def mock_post(url, **kwargs):
            proofs.append(kwargs["headers"].get("DPoP"))
            return challenge if len(proofs) == 1 else success

        http = AsyncMock()
        http.post = mock_post
        ctx = MagicMock()
        ctx.__aenter__ = AsyncMock(return_value=http)
        ctx.__aexit__ = AsyncMock(return_value=False)
        client._get_http_client = MagicMock(return_value=ctx)

        await client.passwordless.verify(
            VerifyPasswordlessOtpOptions(
                connection="email", email="user@example.com", verification_code="123456"
            ),
            dpop_key=dpop_key,
        )
        assert len(proofs) == 2
        assert proofs[0] != proofs[1]

    @pytest.mark.asyncio
    async def test_verify_dpop_rejects_bearer_downgrade(self, mocker):
        client = _make_client()
        mocker.patch.object(client, "_get_oidc_metadata_cached", return_value=METADATA)
        dpop_key = jwk.JWK.generate(kty="EC", crv="P-256")
        http = _mock_http(
            client,
            200,
            {"access_token": "at", "token_type": "Bearer", "id_token": "idt", "expires_in": 3600},
        )
        http.post.return_value.headers = {}

        with pytest.raises(PasswordlessVerifyError, match="DPoP token binding failed"):
            await client.passwordless.verify(
                VerifyPasswordlessOtpOptions(
                    connection="email", email="user@example.com", verification_code="123456"
                ),
                dpop_key=dpop_key,
            )
        client._state_store.set.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_verify_rejects_unsolicited_dpop_upgrade(self, mocker):
        # Server returns a DPoP-bound token even though no dpop_key was
        # supplied: storing it as Bearer would silently fail open, so reject.
        client = _make_client()
        mocker.patch.object(client, "_get_oidc_metadata_cached", return_value=METADATA)
        http = _mock_http(
            client,
            200,
            {"access_token": "at", "token_type": "DPoP", "id_token": "idt", "expires_in": 3600},
        )
        http.post.return_value.headers = {}

        with pytest.raises(PasswordlessVerifyError, match="no dpop_key was"):
            await client.passwordless.verify(
                VerifyPasswordlessOtpOptions(
                    connection="email", email="user@example.com", verification_code="123456"
                )
            )
        client._state_store.set.assert_not_awaited()
