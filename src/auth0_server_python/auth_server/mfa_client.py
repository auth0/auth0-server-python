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
        secret: str,
        state_store=None,
        state_identifier: str = "_a0_session"
    ):
        self._domain = domain
        self._base_url = f"https://{domain}"
        self._client_id = client_id
        self._client_secret = client_secret
        self._secret = secret
        self._state_store = state_store
        self._state_identifier = state_identifier

    # ============================================================================
    # MFA TOKEN ENCRYPTION / DECRYPTION
    # ============================================================================

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

    # ============================================================================
    # MFA API OPERATIONS
    # ============================================================================

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
                Required: 'mfa_token', 'factor_type' (otp, sms, voice, email).
                Optional: 'phone_number', 'email'.

        Returns:
            OtpEnrollmentResponse or OobEnrollmentResponse.

        Raises:
            MfaEnrollmentError: When enrollment fails.
        """
        mfa_token = options["mfa_token"]
        factor_type = options["factor_type"]
        url = f"{self._base_url}/mfa/associate"

        # Map factor_type to Auth0 API parameters
        if factor_type == "otp":
            authenticator_type = "otp"
            oob_channels = None
        elif factor_type in ["sms", "voice", "email"]:
            authenticator_type = "oob"
            oob_channels = factor_type
        else:
            raise MfaEnrollmentError(
                f"Unsupported factor_type: {factor_type}. Supported types: otp, sms, voice, email"
            )

        # Build API request body
        body: dict[str, Any] = {
            "authenticator_types": authenticator_type
        }

        if oob_channels:
            body["oob_channels"] = oob_channels

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

    async def challenge_authenticator(
        self,
        options: dict[str, Any]
    ) -> ChallengeResponse:
        """
        Initiates an MFA challenge for user verification.

        Args:
            options: Dict containing 'mfa_token', 'factor_type' (otp, sms, voice, email),
                and optionally 'authenticator_id'.

        Returns:
            ChallengeResponse with challenge details.

        Raises:
            MfaChallengeError: When the challenge fails.
        """
        mfa_token = options["mfa_token"]
        factor_type = options["factor_type"]
        url = f"{self._base_url}/mfa/challenge"

        # Map factor_type to Auth0 API challenge_type
        if factor_type == "otp":
            challenge_type = "otp"
        elif factor_type in ["sms", "voice", "email"]:
            challenge_type = "oob"
        else:
            raise MfaChallengeError(
                f"Unsupported factor_type: {factor_type}. Supported types: otp, sms, voice, email"
            )

        body: dict[str, Any] = {
            "mfa_token": mfa_token,
            "client_id": self._client_id,
            "challenge_type": challenge_type
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
                - 'persist': bool (optional, default=False) - Persist tokens to state store
                - 'audience': str (optional, required if persist=True) - Audience for token_set
                - 'scope': str (optional) - Scope for token_set
                - 'store_options': dict (optional) - Store-specific options

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
                verify_response = MfaVerifyResponse(**token_response)

                # Persist tokens to state store if requested
                if options.get("persist") and self._state_store:
                    await self._persist_mfa_tokens(
                        verify_response=verify_response,
                        options=options
                    )

                return verify_response

        except (MfaVerifyError, MfaRequiredError):
            raise
        except Exception as e:
            raise MfaVerifyError(
                f"Unexpected error during MFA verification: {str(e)}"
            )

    async def _persist_mfa_tokens(
        self,
        verify_response: MfaVerifyResponse,
        options: dict[str, Any]
    ) -> None:
        """
        Persist MFA verification tokens to the state store.

        Updates the session with the new access_token and id_token from MFA verification.

        Args:
            verify_response: The response from verify() containing tokens
            options: Dict containing:
                - 'audience': str - Audience for token_set
                - 'scope': str (optional) - Scope for token_set
                - 'store_options': dict (optional) - Store-specific options
        """
        import time

        from auth0_server_python.auth_types import StateData, TokenSet

        audience = options.get("audience")
        scope = options.get("scope")
        store_options = options.get("store_options")

        if not audience:
            raise MfaVerifyError(
                "audience is required when persist=True"
            )

        try:
            # Get existing state
            state_data = await self._state_store.get(
                self._state_identifier,
                store_options
            )

            if not state_data:
                raise MfaVerifyError(
                    "No existing session found to update with MFA tokens"
                )

            # Parse state data
            existing_state = StateData(**state_data) if isinstance(state_data, dict) else state_data

            # Update id_token if present
            if verify_response.id_token:
                existing_state.id_token = verify_response.id_token

            # Create token_set for the access_token
            expires_in = verify_response.get("expires_in", 86400)  # Default 24 hours
            expires_at = int(time.time()) + expires_in

            new_token_set = TokenSet(
                audience=audience,
                access_token=verify_response.access_token,
                scope=scope,
                expires_at=expires_at
            )

            # Add to token_sets, replacing any existing token_set for this audience
            existing_state.token_sets = [
                ts for ts in existing_state.token_sets if ts.audience != audience
            ]
            existing_state.token_sets.append(new_token_set)

            # Persist updated state
            await self._state_store.set(
                self._state_identifier,
                existing_state.model_dump() if hasattr(existing_state, 'model_dump') else existing_state,
                options=store_options
            )

        except MfaVerifyError:
            raise
        except Exception as e:
            raise MfaVerifyError(
                f"Failed to persist MFA tokens to state store: {str(e)}"
            )
