"""
MFA Client for auth0-server-python SDK.
Handles Multi-Factor Authentication operations against the Auth0 MFA API.
"""

import time
from typing import Any, Optional

import httpx
from auth0_server_python.auth_schemes.bearer_auth import BearerAuth
from auth0_server_python.auth_types import (
    AuthenticatorResponse,
    ChallengeResponse,
    EnrollmentResponse,
    MfaRequirements,
    MfaTokenContext,
    MfaVerifyResponse,
    OobEnrollmentResponse,
    OtpEnrollmentResponse,
)
from auth0_server_python.encryption.encrypt import decrypt, encrypt
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

DEFAULT_MFA_TOKEN_TTL = 300  # 5 minutes


class MfaClient:
    """
    Client for Auth0 MFA API operations.

    Provides methods for listing authenticators, enrolling new authenticators,
    deleting authenticators, challenging authenticators, and verifying MFA codes.

    All operations require an mfa_token which is obtained either:
    1. From MfaRequiredError raised during get_access_token() (encrypted)
    2. Directly from the Auth0 MFA challenge response (raw)
    """

    def __init__(
        self,
        domain: str,
        client_id: str,
        client_secret: str,
        secret: str
    ):
        self._domain = domain
        self._base_url = f"https://{domain}"
        self._client_id = client_id
        self._client_secret = client_secret
        self._secret = secret

    def encrypt_mfa_token(
        self,
        raw_mfa_token: str,
        audience: str,
        scope: str,
        mfa_requirements: Optional[MfaRequirements] = None,
        ttl: int = DEFAULT_MFA_TOKEN_TTL
    ) -> str:
        """Encrypt an MFA token with context for secure client-side storage."""
        context = MfaTokenContext(
            mfa_token=raw_mfa_token,
            audience=audience,
            scope=scope,
            mfa_requirements=mfa_requirements,
            created_at=int(time.time())
        )
        return encrypt(context.model_dump(), self._secret, "mfa_token")

    def decrypt_mfa_token(self, encrypted_token: str) -> MfaTokenContext:
        """Decrypt an MFA token and validate TTL."""
        try:
            payload = decrypt(encrypted_token, self._secret, "mfa_token")
            context = MfaTokenContext(**payload)
        except Exception:
            raise MfaTokenInvalidError()

        # Check TTL
        elapsed = int(time.time()) - context.created_at
        if elapsed > DEFAULT_MFA_TOKEN_TTL:
            raise MfaTokenExpiredError()

        return context

    async def list_authenticators(
        self,
        options: dict[str, Any]
    ) -> list[AuthenticatorResponse]:
        """
        Lists all MFA authenticators enrolled by the user.

        Args:
            options: Dict containing 'mfa_token' (encrypted or raw).

        Returns:
            List of enrolled authenticators.

        Raises:
            MfaListAuthenticatorsError: When the request fails.
        """
        mfa_token = options["mfa_token"]
        url = f"{self._base_url}/mfa/authenticators"

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    url,
                    auth=BearerAuth(mfa_token)
                )

                if response.status_code != 200:
                    error_data = response.json()
                    raise MfaListAuthenticatorsError(
                        error_data.get("error_description", "Failed to list authenticators"),
                        error_data
                    )

                api_response = response.json()
                return [AuthenticatorResponse(**auth) for auth in api_response]

        except MfaListAuthenticatorsError:
            raise
        except Exception as e:
            raise MfaListAuthenticatorsError(
                f"Unexpected error listing authenticators: {str(e)}"
            )

    async def enroll_authenticator(
        self,
        options: dict[str, Any]
    ) -> EnrollmentResponse:
        """
        Enrolls a new MFA authenticator for the user.

        Args:
            options: Dict containing enrollment parameters.
                Required: 'mfa_token', 'authenticator_types'.
                Optional: 'oob_channels', 'phone_number', 'email'.

        Returns:
            OtpEnrollmentResponse or OobEnrollmentResponse.

        Raises:
            MfaEnrollmentError: When enrollment fails.
        """
        mfa_token = options["mfa_token"]
        url = f"{self._base_url}/mfa/associate"

        # Build API request body
        body: dict[str, Any] = {
            "authenticator_types": options["authenticator_types"]
        }

        if "oob_channels" in options:
            body["oob_channels"] = options["oob_channels"]

        if "phone_number" in options and options["phone_number"]:
            body["phone_number"] = options["phone_number"]

        if "email" in options and options["email"]:
            body["email"] = options["email"]

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    url,
                    json=body,
                    auth=BearerAuth(mfa_token),
                    headers={"Content-Type": "application/json"}
                )

                if response.status_code != 200:
                    error_data = response.json()
                    raise MfaEnrollmentError(
                        error_data.get("error_description", "Failed to enroll authenticator"),
                        error_data
                    )

                api_response = response.json()
                authenticator_type = api_response.get("authenticator_type")

                if authenticator_type == "otp":
                    return OtpEnrollmentResponse(**api_response)
                elif authenticator_type == "oob":
                    return OobEnrollmentResponse(**api_response)
                else:
                    raise MfaEnrollmentError(
                        f"Unexpected authenticator type: {authenticator_type}"
                    )

        except MfaEnrollmentError:
            raise
        except Exception as e:
            raise MfaEnrollmentError(
                f"Unexpected error enrolling authenticator: {str(e)}"
            )

    async def delete_authenticator(
        self,
        options: dict[str, Any]
    ) -> None:
        """
        Deletes an enrolled MFA authenticator.

        Args:
            options: Dict containing 'authenticator_id' and 'mfa_token'.

        Raises:
            MfaDeleteAuthenticatorError: When deletion fails.
        """
        mfa_token = options["mfa_token"]
        authenticator_id = options["authenticator_id"]
        url = f"{self._base_url}/mfa/authenticators/{authenticator_id}"

        try:
            async with httpx.AsyncClient() as client:
                response = await client.delete(
                    url,
                    auth=BearerAuth(mfa_token),
                    headers={"Content-Type": "application/json"}
                )

                if response.status_code != 204:
                    error_data = response.json()
                    raise MfaDeleteAuthenticatorError(
                        error_data.get("error_description", "Failed to delete authenticator"),
                        error_data
                    )

        except MfaDeleteAuthenticatorError:
            raise
        except Exception as e:
            raise MfaDeleteAuthenticatorError(
                f"Unexpected error deleting authenticator: {str(e)}"
            )

    async def challenge_authenticator(
        self,
        options: dict[str, Any]
    ) -> ChallengeResponse:
        """
        Initiates an MFA challenge for user verification.

        Args:
            options: Dict containing 'mfa_token', 'challenge_type',
                and optionally 'authenticator_id'.

        Returns:
            ChallengeResponse with challenge details.

        Raises:
            MfaChallengeError: When the challenge fails.
        """
        mfa_token = options["mfa_token"]
        url = f"{self._base_url}/mfa/challenge"

        body: dict[str, Any] = {
            "mfa_token": mfa_token,
            "client_id": self._client_id,
            "challenge_type": options["challenge_type"]
        }

        if "authenticator_id" in options and options["authenticator_id"]:
            body["authenticator_id"] = options["authenticator_id"]

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    url,
                    json=body,
                    headers={"Content-Type": "application/json"}
                )

                if response.status_code != 200:
                    error_data = response.json()
                    raise MfaChallengeError(
                        error_data.get("error_description", "Failed to challenge authenticator"),
                        error_data
                    )

                api_response = response.json()
                return ChallengeResponse(**api_response)

        except MfaChallengeError:
            raise
        except Exception as e:
            raise MfaChallengeError(
                f"Unexpected error challenging authenticator: {str(e)}"
            )

    async def verify(
        self,
        options: dict[str, Any]
    ) -> MfaVerifyResponse:
        """
        Verifies an MFA code and completes authentication.

        Supports OTP, OOB (with binding code), and recovery code verification.

        If Auth0 returns 'mfa_required' again (chained MFA), raises MfaRequiredError
        with a new encrypted mfa_token.

        Args:
            options: Dict containing 'mfa_token' and one of:
                - 'otp': OTP code
                - 'oob_code' + 'binding_code': OOB verification
                - 'recovery_code': Recovery code

        Returns:
            MfaVerifyResponse with access_token, token_type, etc.

        Raises:
            MfaVerifyError: When verification fails.
            MfaRequiredError: When chained MFA is required.
        """
        mfa_token = options["mfa_token"]

        # Determine grant type and build body
        body: dict[str, Any] = {
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "mfa_token": mfa_token
        }

        if "otp" in options:
            body["grant_type"] = "http://auth0.com/oauth/grant-type/mfa-otp"
            body["otp"] = options["otp"]
        elif "oob_code" in options:
            body["grant_type"] = "http://auth0.com/oauth/grant-type/mfa-oob"
            body["oob_code"] = options["oob_code"]
            body["binding_code"] = options.get("binding_code", "")
        elif "recovery_code" in options:
            body["grant_type"] = "http://auth0.com/oauth/grant-type/mfa-recovery-code"
            body["recovery_code"] = options["recovery_code"]
        else:
            raise MfaVerifyError(
                "No verification credential provided (otp, oob_code, or recovery_code)"
            )

        try:
            token_endpoint = f"{self._base_url}/oauth/token"

            async with httpx.AsyncClient() as client:
                response = await client.post(
                    token_endpoint,
                    data=body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )

                if response.status_code != 200:
                    error_data = response.json()

                    # Handle chained MFA
                    if error_data.get("error") == "mfa_required":
                        new_mfa_token = error_data.get("mfa_token")
                        mfa_requirements_data = error_data.get("mfa_requirements")
                        mfa_requirements = None
                        if mfa_requirements_data:
                            mfa_requirements = MfaRequirements(**mfa_requirements_data)

                        raise MfaRequiredError(
                            error_data.get("error_description", "Additional MFA factor required"),
                            mfa_token=new_mfa_token,
                            mfa_requirements=mfa_requirements
                        )

                    raise MfaVerifyError(
                        error_data.get("error_description", "MFA verification failed"),
                        error_data
                    )

                token_response = response.json()
                return MfaVerifyResponse(**token_response)

        except (MfaVerifyError, MfaRequiredError):
            raise
        except Exception as e:
            raise MfaVerifyError(
                f"Unexpected error during MFA verification: {str(e)}"
            )
