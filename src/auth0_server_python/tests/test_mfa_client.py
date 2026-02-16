"""
Tests for MfaClient — MFA API operations.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from auth0_server_python.auth_server.mfa_client import DEFAULT_MFA_TOKEN_TTL, MfaClient
from auth0_server_python.auth_types import (
    AuthenticatorResponse,
    ChallengeResponse,
    MfaRequirements,
    MfaVerifyResponse,
    OobEnrollmentResponse,
    OtpEnrollmentResponse,
)
from auth0_server_python.error import (
    MfaChallengeError,
    MfaDeleteAuthenticatorError,
    MfaEnrollmentError,
    MfaListAuthenticatorsError,
    MfaRequiredError,
    MfaTokenExpiredError,
    MfaTokenInvalidError,
    MfaVerifyError,
)

# Shared fixtures
DOMAIN = "auth0.local"
CLIENT_ID = "<client_id>"
CLIENT_SECRET = "<client_secret>"
SECRET = "test-secret-long-enough-for-encryption"


def _make_client() -> MfaClient:
    return MfaClient(
        domain=DOMAIN,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        secret=SECRET
    )


# ── Constructor ──────────────────────────────────────────────────────────────

class TestMfaClientConstructor:
    def test_constructor_sets_properties(self):
        client = _make_client()
        assert client._domain == DOMAIN
        assert client._base_url == f"https://{DOMAIN}"
        assert client._client_id == CLIENT_ID
        assert client._client_secret == CLIENT_SECRET
        assert client._secret == SECRET


# ── Token Encryption / Decryption ────────────────────────────────────────────

class TestMfaTokenEncryption:
    def test_encrypt_decrypt_roundtrip(self):
        client = _make_client()
        requirements = MfaRequirements(
            enroll=[{"type": "otp"}],
            challenge=[{"type": "oob"}]
        )
        encrypted = client.encrypt_mfa_token(
            raw_mfa_token="raw_token_123",
            audience="https://api.example.com",
            scope="openid profile",
            mfa_requirements=requirements
        )
        assert isinstance(encrypted, str)
        assert encrypted != "raw_token_123"

        context = client.decrypt_mfa_token(encrypted)
        assert context.mfa_token == "raw_token_123"
        assert context.audience == "https://api.example.com"
        assert context.scope == "openid profile"
        assert context.mfa_requirements is not None

    def test_decrypt_expired_token_raises(self, mocker):
        client = _make_client()
        mocker.patch("auth0_server_python.auth_server.mfa_client.time.time",
                     return_value=1000)
        encrypted = client.encrypt_mfa_token(
            raw_mfa_token="raw",
            audience="aud",
            scope="scope"
        )

        # Move time forward past TTL
        mocker.patch("auth0_server_python.auth_server.mfa_client.time.time",
                     return_value=1000 + DEFAULT_MFA_TOKEN_TTL + 1)
        with pytest.raises(MfaTokenExpiredError):
            client.decrypt_mfa_token(encrypted)

    def test_decrypt_invalid_token_raises(self):
        client = _make_client()
        with pytest.raises(MfaTokenInvalidError):
            client.decrypt_mfa_token("not-a-valid-encrypted-token")

    def test_decrypt_tampered_token_raises(self):
        client = _make_client()
        encrypted = client.encrypt_mfa_token(
            raw_mfa_token="raw", audience="aud", scope="scope"
        )
        tampered = encrypted[:-5] + "XXXXX"
        with pytest.raises(MfaTokenInvalidError):
            client.decrypt_mfa_token(tampered)

    def test_encrypt_without_mfa_requirements(self):
        client = _make_client()
        encrypted = client.encrypt_mfa_token(
            raw_mfa_token="raw", audience="aud", scope="scope"
        )
        context = client.decrypt_mfa_token(encrypted)
        assert context.mfa_requirements is None


# ── list_authenticators ──────────────────────────────────────────────────────

class TestListAuthenticators:
    @pytest.mark.asyncio
    async def test_list_authenticators_success(self, mocker):
        client = _make_client()
        response = AsyncMock()
        response.status_code = 200
        response.json = MagicMock(return_value=[
            {
                "id": "auth|123",
                "authenticator_type": "otp",
                "active": True,
                "name": "Google Authenticator"
            },
            {
                "id": "auth|456",
                "authenticator_type": "oob",
                "active": True,
                "oob_channels": ["sms"]
            }
        ])
        mocker.patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=response)

        result = await client.list_authenticators({"mfa_token": "mfa_tok"})
        assert len(result) == 2
        assert isinstance(result[0], AuthenticatorResponse)
        assert result[0].id == "auth|123"
        assert result[1].oob_channels == ["sms"]

    @pytest.mark.asyncio
    async def test_list_authenticators_api_error(self, mocker):
        client = _make_client()
        response = AsyncMock()
        response.status_code = 401
        response.json = MagicMock(return_value={
            "error": "invalid_token",
            "error_description": "Invalid MFA token"
        })
        mocker.patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=response)

        with pytest.raises(MfaListAuthenticatorsError) as exc:
            await client.list_authenticators({"mfa_token": "bad_tok"})
        assert "Invalid MFA token" in str(exc.value)

    @pytest.mark.asyncio
    async def test_list_authenticators_unexpected_error(self, mocker):
        client = _make_client()
        mocker.patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=Exception("network down"))

        with pytest.raises(MfaListAuthenticatorsError) as exc:
            await client.list_authenticators({"mfa_token": "tok"})
        assert "network down" in str(exc.value)


# ── enroll_authenticator ─────────────────────────────────────────────────────

class TestEnrollAuthenticator:
    @pytest.mark.asyncio
    async def test_enroll_otp_success(self, mocker):
        client = _make_client()
        response = AsyncMock()
        response.status_code = 200
        response.json = MagicMock(return_value={
            "authenticator_type": "otp",
            "secret": "JBSWY3DPEHPK3PXP",
            "barcode_uri": "otpauth://totp/auth0:user?secret=JBSWY3DPEHPK3PXP",
            "recovery_codes": ["code1", "code2"]
        })
        mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

        result = await client.enroll_authenticator({
            "mfa_token": "tok",
            "authenticator_types": ["otp"]
        })
        assert isinstance(result, OtpEnrollmentResponse)
        assert result.secret == "JBSWY3DPEHPK3PXP"
        assert result.recovery_codes == ["code1", "code2"]

    @pytest.mark.asyncio
    async def test_enroll_sms_oob_success(self, mocker):
        client = _make_client()
        response = AsyncMock()
        response.status_code = 200
        response.json = MagicMock(return_value={
            "authenticator_type": "oob",
            "oob_channel": "sms",
            "oob_code": "oob_123",
            "binding_method": "prompt"
        })
        mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

        result = await client.enroll_authenticator({
            "mfa_token": "tok",
            "authenticator_types": ["oob"],
            "oob_channels": ["sms"],
            "phone_number": "+1234567890"
        })
        assert isinstance(result, OobEnrollmentResponse)
        assert result.oob_channel == "sms"

    @pytest.mark.asyncio
    async def test_enroll_email_oob_success(self, mocker):
        client = _make_client()
        response = AsyncMock()
        response.status_code = 200
        response.json = MagicMock(return_value={
            "authenticator_type": "oob",
            "oob_channel": "email",
            "oob_code": "oob_email_123"
        })
        mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

        result = await client.enroll_authenticator({
            "mfa_token": "tok",
            "authenticator_types": ["oob"],
            "oob_channels": ["email"],
            "email": "user@example.com"
        })
        assert isinstance(result, OobEnrollmentResponse)
        assert result.oob_channel == "email"

    @pytest.mark.asyncio
    async def test_enroll_api_error(self, mocker):
        client = _make_client()
        response = AsyncMock()
        response.status_code = 400
        response.json = MagicMock(return_value={
            "error": "invalid_request",
            "error_description": "Bad enrollment request"
        })
        mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

        with pytest.raises(MfaEnrollmentError) as exc:
            await client.enroll_authenticator({
                "mfa_token": "tok",
                "authenticator_types": ["otp"]
            })
        assert "Bad enrollment request" in str(exc.value)

    @pytest.mark.asyncio
    async def test_enroll_unexpected_authenticator_type(self, mocker):
        client = _make_client()
        response = AsyncMock()
        response.status_code = 200
        response.json = MagicMock(return_value={
            "authenticator_type": "unknown_type"
        })
        mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

        with pytest.raises(MfaEnrollmentError) as exc:
            await client.enroll_authenticator({
                "mfa_token": "tok",
                "authenticator_types": ["unknown_type"]
            })
        assert "Unexpected authenticator type" in str(exc.value)


# ── delete_authenticator ─────────────────────────────────────────────────────

class TestDeleteAuthenticator:
    @pytest.mark.asyncio
    async def test_delete_authenticator_success(self, mocker):
        client = _make_client()
        response = AsyncMock()
        response.status_code = 204
        mocker.patch("httpx.AsyncClient.delete", new_callable=AsyncMock, return_value=response)

        result = await client.delete_authenticator({
            "mfa_token": "tok",
            "authenticator_id": "auth|123"
        })
        assert result is None

    @pytest.mark.asyncio
    async def test_delete_authenticator_api_error(self, mocker):
        client = _make_client()
        response = AsyncMock()
        response.status_code = 404
        response.json = MagicMock(return_value={
            "error": "not_found",
            "error_description": "Authenticator not found"
        })
        mocker.patch("httpx.AsyncClient.delete", new_callable=AsyncMock, return_value=response)

        with pytest.raises(MfaDeleteAuthenticatorError) as exc:
            await client.delete_authenticator({
                "mfa_token": "tok",
                "authenticator_id": "auth|invalid"
            })
        assert "Authenticator not found" in str(exc.value)

    @pytest.mark.asyncio
    async def test_delete_authenticator_unexpected_error(self, mocker):
        client = _make_client()
        mocker.patch("httpx.AsyncClient.delete", new_callable=AsyncMock, side_effect=Exception("timeout"))

        with pytest.raises(MfaDeleteAuthenticatorError) as exc:
            await client.delete_authenticator({
                "mfa_token": "tok",
                "authenticator_id": "auth|123"
            })
        assert "timeout" in str(exc.value)


# ── challenge_authenticator ──────────────────────────────────────────────────

class TestChallengeAuthenticator:
    @pytest.mark.asyncio
    async def test_challenge_otp_success(self, mocker):
        client = _make_client()
        response = AsyncMock()
        response.status_code = 200
        response.json = MagicMock(return_value={
            "challenge_type": "otp"
        })
        mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

        result = await client.challenge_authenticator({
            "mfa_token": "tok",
            "challenge_type": "otp"
        })
        assert isinstance(result, ChallengeResponse)
        assert result.challenge_type == "otp"

    @pytest.mark.asyncio
    async def test_challenge_oob_success(self, mocker):
        client = _make_client()
        response = AsyncMock()
        response.status_code = 200
        response.json = MagicMock(return_value={
            "challenge_type": "oob",
            "oob_code": "oob_challenge_123",
            "binding_method": "prompt"
        })
        mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

        result = await client.challenge_authenticator({
            "mfa_token": "tok",
            "challenge_type": "oob",
            "authenticator_id": "auth|456"
        })
        assert result.challenge_type == "oob"
        assert result.oob_code == "oob_challenge_123"

    @pytest.mark.asyncio
    async def test_challenge_api_error(self, mocker):
        client = _make_client()
        response = AsyncMock()
        response.status_code = 403
        response.json = MagicMock(return_value={
            "error": "invalid_token",
            "error_description": "Token expired"
        })
        mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

        with pytest.raises(MfaChallengeError) as exc:
            await client.challenge_authenticator({
                "mfa_token": "tok",
                "challenge_type": "otp"
            })
        assert "Token expired" in str(exc.value)


# ── verify ───────────────────────────────────────────────────────────────────

class TestVerify:
    @pytest.mark.asyncio
    async def test_verify_otp_success(self, mocker):
        client = _make_client()
        response = AsyncMock()
        response.status_code = 200
        response.json = MagicMock(return_value={
            "access_token": "new_at",
            "token_type": "Bearer",
            "expires_in": 3600
        })
        mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

        result = await client.verify({
            "mfa_token": "tok",
            "otp": "123456"
        })
        assert isinstance(result, MfaVerifyResponse)
        assert result.access_token == "new_at"

    @pytest.mark.asyncio
    async def test_verify_oob_success(self, mocker):
        client = _make_client()
        response = AsyncMock()
        response.status_code = 200
        response.json = MagicMock(return_value={
            "access_token": "new_at",
            "token_type": "Bearer",
            "expires_in": 3600
        })
        mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

        result = await client.verify({
            "mfa_token": "tok",
            "oob_code": "oob_123",
            "binding_code": "bind_456"
        })
        assert isinstance(result, MfaVerifyResponse)

    @pytest.mark.asyncio
    async def test_verify_recovery_code_success(self, mocker):
        client = _make_client()
        response = AsyncMock()
        response.status_code = 200
        response.json = MagicMock(return_value={
            "access_token": "new_at",
            "token_type": "Bearer",
            "expires_in": 3600
        })
        mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

        result = await client.verify({
            "mfa_token": "tok",
            "recovery_code": "ABCD-1234-EFGH"
        })
        assert isinstance(result, MfaVerifyResponse)

    @pytest.mark.asyncio
    async def test_verify_no_credential_raises(self):
        client = _make_client()
        with pytest.raises(MfaVerifyError) as exc:
            await client.verify({"mfa_token": "tok"})
        assert "No verification credential" in str(exc.value)

    @pytest.mark.asyncio
    async def test_verify_wrong_code_raises(self, mocker):
        client = _make_client()
        response = AsyncMock()
        response.status_code = 403
        response.json = MagicMock(return_value={
            "error": "invalid_grant",
            "error_description": "Invalid OTP"
        })
        mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

        with pytest.raises(MfaVerifyError) as exc:
            await client.verify({"mfa_token": "tok", "otp": "000000"})
        assert "Invalid OTP" in str(exc.value)

    @pytest.mark.asyncio
    async def test_verify_chained_mfa_raises_mfa_required(self, mocker):
        client = _make_client()
        response = AsyncMock()
        response.status_code = 403
        response.json = MagicMock(return_value={
            "error": "mfa_required",
            "error_description": "Additional factor required",
            "mfa_token": "new_raw_mfa_token"
        })
        mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

        with pytest.raises(MfaRequiredError) as exc:
            await client.verify({"mfa_token": "tok", "otp": "123456"})
        assert exc.value.mfa_token == "new_raw_mfa_token"
        assert exc.value.code == "mfa_required"

    @pytest.mark.asyncio
    async def test_verify_unexpected_error(self, mocker):
        client = _make_client()
        mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, side_effect=Exception("connection reset"))

        with pytest.raises(MfaVerifyError) as exc:
            await client.verify({"mfa_token": "tok", "otp": "123456"})
        assert "connection reset" in str(exc.value)
