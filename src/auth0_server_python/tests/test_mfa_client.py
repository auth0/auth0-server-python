"""Tests for MfaClient — MFA API operations."""

import time
from unittest.mock import ANY, AsyncMock, MagicMock

import pytest
from auth0_server_python.auth_server.mfa_client import DEFAULT_MFA_TOKEN_TTL, MfaClient
from auth0_server_python.auth_types import (
    AuthenticatorResponse,
    ChallengeResponse,
    MfaRequirements,
    MfaTokenContext,
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


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def mfa_client():
    return MfaClient(
        domain="auth0.local",
        client_id="test_client_id",
        client_secret="test_client_secret",
        secret="test-encryption-secret-that-is-long-enough"
    )


# ── Token Encryption / Decryption ────────────────────────────────────────────


class TestMfaTokenEncryption:
    def test_encrypt_decrypt_roundtrip(self, mfa_client):
        encrypted = mfa_client.encrypt_mfa_token(
            raw_mfa_token="raw_token_123",
            audience="https://api.example.com",
            scope="openid profile",
            mfa_requirements=MfaRequirements(
                challenge=[{"type": "otp"}]
            )
        )

        assert isinstance(encrypted, str)
        assert encrypted != "raw_token_123"

        context = mfa_client.decrypt_mfa_token(encrypted)
        assert isinstance(context, MfaTokenContext)
        assert context.mfa_token == "raw_token_123"
        assert context.audience == "https://api.example.com"
        assert context.scope == "openid profile"

    def test_decrypt_expired_token_raises(self, mfa_client, mocker):
        # Encrypt a token
        encrypted = mfa_client.encrypt_mfa_token(
            raw_mfa_token="raw_token",
            audience="aud",
            scope="scope"
        )

        # Fast-forward time past TTL
        mocker.patch("auth0_server_python.auth_server.mfa_client.time.time",
                      return_value=time.time() + DEFAULT_MFA_TOKEN_TTL + 10)

        with pytest.raises(MfaTokenExpiredError):
            mfa_client.decrypt_mfa_token(encrypted)

    def test_decrypt_invalid_token_raises(self, mfa_client):
        with pytest.raises(MfaTokenInvalidError):
            mfa_client.decrypt_mfa_token("not-a-valid-jwe-token")

    def test_decrypt_tampered_token_raises(self, mfa_client):
        encrypted = mfa_client.encrypt_mfa_token(
            raw_mfa_token="raw_token",
            audience="aud",
            scope="scope"
        )

        # Tamper with the token
        with pytest.raises(MfaTokenInvalidError):
            mfa_client.decrypt_mfa_token(encrypted + "tampered")

    def test_encrypt_without_mfa_requirements(self, mfa_client):
        encrypted = mfa_client.encrypt_mfa_token(
            raw_mfa_token="raw_token",
            audience="aud",
            scope="scope"
        )

        context = mfa_client.decrypt_mfa_token(encrypted)
        assert context.mfa_requirements is None


# ── list_authenticators ──────────────────────────────────────────────────────


class TestListAuthenticators:
    @pytest.mark.asyncio
    async def test_list_authenticators_success(self, mfa_client, mocker):
        response = AsyncMock()
        response.status_code = 200
        response.json = MagicMock(return_value=[
            {
                "id": "auth0|totp",
                "authenticator_type": "otp",
                "active": True,
                "name": "Google Authenticator"
            },
            {
                "id": "auth0|sms",
                "authenticator_type": "oob",
                "active": True,
                "oob_channels": ["sms"]
            }
        ])

        mocker.patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=response)

        result = await mfa_client.list_authenticators({"mfa_token": "test_mfa_token"})

        assert len(result) == 2
        assert isinstance(result[0], AuthenticatorResponse)
        assert result[0].id == "auth0|totp"
        assert result[0].authenticator_type == "otp"
        assert result[0].active is True
        assert result[1].oob_channels == ["sms"]

    @pytest.mark.asyncio
    async def test_list_authenticators_api_error(self, mfa_client, mocker):
        response = AsyncMock()
        response.status_code = 401
        response.json = MagicMock(return_value={
            "error": "invalid_token",
            "error_description": "Invalid MFA token"
        })

        mocker.patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=response)

        with pytest.raises(MfaListAuthenticatorsError) as exc:
            await mfa_client.list_authenticators({"mfa_token": "bad_token"})

        assert "Invalid MFA token" in str(exc.value)

    @pytest.mark.asyncio
    async def test_list_authenticators_unexpected_error(self, mfa_client, mocker):
        mocker.patch("httpx.AsyncClient.get", new_callable=AsyncMock,
                      side_effect=Exception("Connection failed"))

        with pytest.raises(MfaListAuthenticatorsError) as exc:
            await mfa_client.list_authenticators({"mfa_token": "token"})

        assert "Unexpected error" in str(exc.value)


# ── enroll_authenticator ─────────────────────────────────────────────────────


class TestEnrollAuthenticator:
    @pytest.mark.asyncio
    async def test_enroll_otp_success(self, mfa_client, mocker):
        response = AsyncMock()
        response.status_code = 200
        response.json = MagicMock(return_value={
            "authenticator_type": "otp",
            "secret": "JBSWY3DPEHPK3PXP",
            "barcode_uri": "otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP",
            "recovery_codes": ["ABC123"]
        })

        mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

        result = await mfa_client.enroll_authenticator({
            "mfa_token": "test_token",
            "authenticator_types": ["otp"]
        })

        assert isinstance(result, OtpEnrollmentResponse)
        assert result.authenticator_type == "otp"
        assert result.secret == "JBSWY3DPEHPK3PXP"
        assert result.recovery_codes == ["ABC123"]

    @pytest.mark.asyncio
    async def test_enroll_sms_oob_success(self, mfa_client, mocker):
        response = AsyncMock()
        response.status_code = 200
        response.json = MagicMock(return_value={
            "authenticator_type": "oob",
            "oob_channel": "sms",
            "oob_code": "oob_code_123",
            "binding_method": "prompt"
        })

        mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

        result = await mfa_client.enroll_authenticator({
            "mfa_token": "test_token",
            "authenticator_types": ["oob"],
            "oob_channels": ["sms"],
            "phone_number": "+1234567890"
        })

        assert isinstance(result, OobEnrollmentResponse)
        assert result.authenticator_type == "oob"
        assert result.oob_channel == "sms"

    @pytest.mark.asyncio
    async def test_enroll_email_oob_success(self, mfa_client, mocker):
        response = AsyncMock()
        response.status_code = 200
        response.json = MagicMock(return_value={
            "authenticator_type": "oob",
            "oob_channel": "email",
            "oob_code": "oob_code_456"
        })

        mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

        result = await mfa_client.enroll_authenticator({
            "mfa_token": "test_token",
            "authenticator_types": ["oob"],
            "oob_channels": ["email"],
            "email": "user@example.com"
        })

        assert isinstance(result, OobEnrollmentResponse)
        assert result.oob_channel == "email"

    @pytest.mark.asyncio
    async def test_enroll_api_error(self, mfa_client, mocker):
        response = AsyncMock()
        response.status_code = 403
        response.json = MagicMock(return_value={
            "error": "forbidden",
            "error_description": "Enrollment not allowed"
        })

        mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

        with pytest.raises(MfaEnrollmentError) as exc:
            await mfa_client.enroll_authenticator({
                "mfa_token": "bad_token",
                "authenticator_types": ["otp"]
            })

        assert "Enrollment not allowed" in str(exc.value)

    @pytest.mark.asyncio
    async def test_enroll_unexpected_authenticator_type(self, mfa_client, mocker):
        response = AsyncMock()
        response.status_code = 200
        response.json = MagicMock(return_value={
            "authenticator_type": "unknown_type"
        })

        mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

        with pytest.raises(MfaEnrollmentError) as exc:
            await mfa_client.enroll_authenticator({
                "mfa_token": "test_token",
                "authenticator_types": ["unknown"]
            })

        assert "Unexpected authenticator type" in str(exc.value)


# ── delete_authenticator ─────────────────────────────────────────────────────


class TestDeleteAuthenticator:
    @pytest.mark.asyncio
    async def test_delete_authenticator_success(self, mfa_client, mocker):
        response = AsyncMock()
        response.status_code = 204

        mocker.patch("httpx.AsyncClient.delete", new_callable=AsyncMock, return_value=response)

        result = await mfa_client.delete_authenticator({
            "mfa_token": "test_token",
            "authenticator_id": "auth0|totp"
        })

        assert result is None

    @pytest.mark.asyncio
    async def test_delete_authenticator_api_error(self, mfa_client, mocker):
        response = AsyncMock()
        response.status_code = 404
        response.json = MagicMock(return_value={
            "error": "not_found",
            "error_description": "Authenticator not found"
        })

        mocker.patch("httpx.AsyncClient.delete", new_callable=AsyncMock, return_value=response)

        with pytest.raises(MfaDeleteAuthenticatorError) as exc:
            await mfa_client.delete_authenticator({
                "mfa_token": "test_token",
                "authenticator_id": "invalid_id"
            })

        assert "Authenticator not found" in str(exc.value)

    @pytest.mark.asyncio
    async def test_delete_authenticator_unexpected_error(self, mfa_client, mocker):
        mocker.patch("httpx.AsyncClient.delete", new_callable=AsyncMock,
                      side_effect=Exception("Network error"))

        with pytest.raises(MfaDeleteAuthenticatorError) as exc:
            await mfa_client.delete_authenticator({
                "mfa_token": "test_token",
                "authenticator_id": "auth0|totp"
            })

        assert "Unexpected error" in str(exc.value)


# ── challenge_authenticator ──────────────────────────────────────────────────


class TestChallengeAuthenticator:
    @pytest.mark.asyncio
    async def test_challenge_otp_success(self, mfa_client, mocker):
        response = AsyncMock()
        response.status_code = 200
        response.json = MagicMock(return_value={
            "challenge_type": "otp"
        })

        mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

        result = await mfa_client.challenge_authenticator({
            "mfa_token": "test_token",
            "challenge_type": "otp"
        })

        assert isinstance(result, ChallengeResponse)
        assert result.challenge_type == "otp"

    @pytest.mark.asyncio
    async def test_challenge_oob_success(self, mfa_client, mocker):
        response = AsyncMock()
        response.status_code = 200
        response.json = MagicMock(return_value={
            "challenge_type": "oob",
            "oob_code": "oob_code_789",
            "binding_method": "prompt"
        })

        mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

        result = await mfa_client.challenge_authenticator({
            "mfa_token": "test_token",
            "challenge_type": "oob",
            "authenticator_id": "auth0|sms"
        })

        assert result.challenge_type == "oob"
        assert result.oob_code == "oob_code_789"
        assert result.binding_method == "prompt"

    @pytest.mark.asyncio
    async def test_challenge_api_error(self, mfa_client, mocker):
        response = AsyncMock()
        response.status_code = 400
        response.json = MagicMock(return_value={
            "error": "invalid_request",
            "error_description": "Unsupported challenge type"
        })

        mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

        with pytest.raises(MfaChallengeError) as exc:
            await mfa_client.challenge_authenticator({
                "mfa_token": "test_token",
                "challenge_type": "otp"
            })

        assert "Unsupported challenge type" in str(exc.value)


# ── verify ───────────────────────────────────────────────────────────────────


class TestVerify:
    @pytest.mark.asyncio
    async def test_verify_otp_success(self, mfa_client, mocker):
        response = AsyncMock()
        response.status_code = 200
        response.json = MagicMock(return_value={
            "access_token": "new_access_token",
            "token_type": "Bearer",
            "expires_in": 86400,
            "scope": "openid profile"
        })

        mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

        result = await mfa_client.verify({
            "mfa_token": "test_token",
            "otp": "123456"
        })

        assert isinstance(result, MfaVerifyResponse)
        assert result.access_token == "new_access_token"
        assert result.token_type == "Bearer"
        assert result.expires_in == 86400

    @pytest.mark.asyncio
    async def test_verify_oob_success(self, mfa_client, mocker):
        response = AsyncMock()
        response.status_code = 200
        response.json = MagicMock(return_value={
            "access_token": "oob_access_token",
            "token_type": "Bearer",
            "expires_in": 86400
        })

        mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

        result = await mfa_client.verify({
            "mfa_token": "test_token",
            "oob_code": "oob_code_123",
            "binding_code": "bind_456"
        })

        assert result.access_token == "oob_access_token"

    @pytest.mark.asyncio
    async def test_verify_recovery_code_success(self, mfa_client, mocker):
        response = AsyncMock()
        response.status_code = 200
        response.json = MagicMock(return_value={
            "access_token": "recovery_access_token",
            "token_type": "Bearer",
            "expires_in": 86400
        })

        mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

        result = await mfa_client.verify({
            "mfa_token": "test_token",
            "recovery_code": "ABCD1234EFGH"
        })

        assert result.access_token == "recovery_access_token"

    @pytest.mark.asyncio
    async def test_verify_no_credential_raises(self, mfa_client):
        with pytest.raises(MfaVerifyError) as exc:
            await mfa_client.verify({"mfa_token": "test_token"})

        assert "No verification credential provided" in str(exc.value)

    @pytest.mark.asyncio
    async def test_verify_wrong_code_raises(self, mfa_client, mocker):
        response = AsyncMock()
        response.status_code = 403
        response.json = MagicMock(return_value={
            "error": "invalid_grant",
            "error_description": "Invalid otp"
        })

        mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

        with pytest.raises(MfaVerifyError) as exc:
            await mfa_client.verify({
                "mfa_token": "test_token",
                "otp": "000000"
            })

        assert "Invalid otp" in str(exc.value)

    @pytest.mark.asyncio
    async def test_verify_chained_mfa_raises_mfa_required(self, mfa_client, mocker):
        response = AsyncMock()
        response.status_code = 403
        response.json = MagicMock(return_value={
            "error": "mfa_required",
            "error_description": "Additional MFA factor required",
            "mfa_token": "new_mfa_token_for_chained",
            "mfa_requirements": {
                "challenge": [{"type": "otp"}]
            }
        })

        mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=response)

        with pytest.raises(MfaRequiredError) as exc:
            await mfa_client.verify({
                "mfa_token": "test_token",
                "otp": "123456"
            })

        assert exc.value.mfa_token == "new_mfa_token_for_chained"
        assert exc.value.mfa_requirements is not None

    @pytest.mark.asyncio
    async def test_verify_unexpected_error(self, mfa_client, mocker):
        mocker.patch("httpx.AsyncClient.post", new_callable=AsyncMock,
                      side_effect=Exception("Connection refused"))

        with pytest.raises(MfaVerifyError) as exc:
            await mfa_client.verify({
                "mfa_token": "test_token",
                "otp": "123456"
            })

        assert "Unexpected error" in str(exc.value)


# ── Constructor ──────────────────────────────────────────────────────────────


class TestMfaClientConstructor:
    def test_constructor_sets_properties(self, mfa_client):
        assert mfa_client._domain == "auth0.local"
        assert mfa_client._base_url == "https://auth0.local"
        assert mfa_client._client_id == "test_client_id"
        assert mfa_client._client_secret == "test_client_secret"
