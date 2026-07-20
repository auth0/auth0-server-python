"""
MFA Client for auth0-server-python SDK.
Handles Multi-Factor Authentication operations against the Auth0 MFA API.
"""

import json
import time
from typing import Any, Callable, Optional, Union

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
    StateData,
    TokenSet,
)
from auth0_server_python.encryption.encrypt import decrypt, encrypt
from auth0_server_python.error import (
    DomainResolverError,
    MfaChallengeError,
    MfaEnrollmentError,
    MfaListAuthenticatorsError,
    MfaRequiredError,
    MfaTokenExpiredError,
    MfaTokenInvalidError,
    MfaVerifyError,
)
from auth0_server_python.utils.helpers import (
    build_domain_resolver_context,
    validate_resolved_domain_value,
)

DEFAULT_MFA_TOKEN_TTL = 300  # 5 minutes
MFA_PENDING_IDENTIFIER = "_a0_mfa_pending"


class MfaClient:
    """
    Client for Auth0 MFA API operations.

    Provides methods for listing authenticators, enrolling new authenticators,
    deleting authenticators, challenging authenticators, and verifying MFA codes.

    All public API methods accept an encrypted mfa_token (as issued by
    MfaRequiredError) and decrypt it internally. Callers never handle the
    raw Auth0 mfa_token directly.
    """

    def __init__(
        self,
        domain: Union[str, Callable, None],
        client_id: str,
        client_secret: str,
        secret: str,
        state_store=None,
        state_identifier: str = "_a0_session",
        headers: Optional[dict[str, str]] = None
    ):
        if callable(domain):
            self._domain = None
            self._domain_resolver = domain
        else:
            self._domain = domain
            self._domain_resolver = None
        self._client_id = client_id
        self._client_secret = client_secret
        self._secret = secret
        self._state_store = state_store
        self._state_identifier = state_identifier
        self._headers = headers or {}

    def _get_http_client(self, **kwargs) -> httpx.AsyncClient:
        """Return an httpx.AsyncClient with default headers injected."""
        headers = {**kwargs.pop("headers", {}), **self._headers}
        return httpx.AsyncClient(headers=headers, **kwargs)

    async def _resolve_base_url(
        self,
        store_options: Optional[dict[str, Any]] = None
    ) -> str:
        """Resolve domain and return base URL for API calls."""
        if self._domain_resolver:
            context = build_domain_resolver_context(store_options)
            try:
                resolved = await self._domain_resolver(context)
                domain = validate_resolved_domain_value(resolved)
            except DomainResolverError:
                raise
            except Exception as e:
                raise DomainResolverError(
                    f"Domain resolver function raised an exception: {str(e)}",
                    original_error=e
                )
        else:
            domain = self._domain
        return f"https://{domain}"

    # ============================================================================
    # MFA TOKEN ENCRYPTION / DECRYPTION
    # ============================================================================

    def _encrypt_mfa_token(
        self,
        raw_mfa_token: str,
        audience: str,
        scope: str,
        mfa_requirements: Optional[MfaRequirements] = None,
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

        elapsed = int(time.time()) - context.created_at
        if elapsed > DEFAULT_MFA_TOKEN_TTL:
            raise MfaTokenExpiredError()

        return context

    # ============================================================================
    # MFA STATE
    # ============================================================================

    @staticmethod
    def _parse_error_body(response: httpx.Response) -> dict[str, Any]:
        """
        Parse an error response body as JSON.

        Falls back to a status-coded stub when the body is not JSON (e.g. a
        gateway 502/504 HTML page), so the caller always gets a readable dict
        rather than a JSON-parser exception folded into the message.

        Args:
            response: The HTTP error response to parse.

        Returns:
            The parsed JSON object, or a stub dict whose 'error_description'
            names the HTTP status when the body is not a JSON object.
        """
        try:
            data = response.json()
        except (json.JSONDecodeError, ValueError):
            data = None
        if not isinstance(data, dict):
            return {
                "error_description": f"Request failed with status {response.status_code}",
            }
        return data

    async def _raise_mfa_required(
        self,
        error_data: dict[str, Any],
        *,
        audience: str,
        scope: str,
        default_description: str,
        store_pending: bool = False,
        store_options: Optional[dict[str, Any]] = None,
    ) -> None:
        """
        Encrypt the server-issued mfa_token and raise MfaRequiredError.

        Shared by every site that handles an `mfa_required` response so the
        encrypt-then-raise behaviour cannot drift between entry points.

        Args:
            error_data: The parsed `mfa_required` error body from Auth0.
            audience: Audience to bind into the encrypted token context.
            scope: Scope to bind into the encrypted token context.
            default_description: Message used when the response omits
                'error_description'.
            store_pending: When True, persist the encrypted token to the state
                store before raising (the passkey grant does; the refresh-token
                path relies on its get_access_token caller instead).
            store_options: Optional options passed to the State Store.

        Returns:
            None. Returns without raising only when the response carries no
            mfa_token, so the caller can fall through to its own typed error.

        Raises:
            MfaRequiredError: When the response carries an mfa_token.
        """
        raw_mfa_token = error_data.get("mfa_token")
        if not raw_mfa_token:
            return
        mfa_requirements_data = error_data.get("mfa_requirements")
        mfa_requirements = (
            MfaRequirements(**mfa_requirements_data) if mfa_requirements_data else None
        )
        encrypted_token = self._encrypt_mfa_token(
            raw_mfa_token=raw_mfa_token,
            audience=audience,
            scope=scope,
            mfa_requirements=mfa_requirements,
        )
        if store_pending and self._state_store:
            # Persist the in-progress MFA token so challenge and verify can
            # proceed without the client carrying the token.
            await self._state_store.set(
                MFA_PENDING_IDENTIFIER,
                {"mfa_token": encrypted_token},
                options=store_options,
            )
        raise MfaRequiredError(
            error_data.get("error_description", default_description),
            mfa_token=encrypted_token,
            mfa_requirements=mfa_requirements,
        )

    # ============================================================================
    # MFA API OPERATIONS
    # ============================================================================

    async def list_authenticators(
        self,
        options: dict[str, Any],
        store_options: Optional[dict[str, Any]] = None
    ) -> list[AuthenticatorResponse]:
        """
        Lists all MFA authenticators enrolled by the user.

        Args:
            options: Dict containing 'mfa_token' (raw, decrypted).
            store_options: Optional options passed to the State Store (e.g. request/response).

        Returns:
            List of enrolled authenticators.

        Raises:
            MfaListAuthenticatorsError: When the request fails.
        """
        mfa_token = options.get("mfa_token")
        if not mfa_token:
            raise MfaTokenInvalidError()
        context = self.decrypt_mfa_token(mfa_token)
        base_url = await self._resolve_base_url(store_options)
        url = f"{base_url}/mfa/authenticators"

        try:
            async with self._get_http_client() as client:
                response = await client.get(
                    url,
                    auth=BearerAuth(context.mfa_token)
                )

                if response.status_code != 200:
                    error_data = self._parse_error_body(response)
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
                "Unexpected error listing authenticators"
            ) from e

    async def enroll_authenticator(
        self,
        options: dict[str, Any],
        store_options: Optional[dict[str, Any]] = None
    ) -> EnrollmentResponse:
        """
        Enrolls a new MFA authenticator for the user.

        Args:
            options: Dict containing enrollment parameters.
                Required: 'mfa_token', 'factor_type' (otp, sms, voice, email, auth0).
                Optional: 'phone_number', 'email'.
            store_options: Optional options passed to the State Store (e.g. request/response).

        Returns:
            OtpEnrollmentResponse or OobEnrollmentResponse.

        Raises:
            MfaEnrollmentError: When enrollment fails.
        """
        mfa_token = options.get("mfa_token")
        if not mfa_token:
            raise MfaTokenInvalidError()
        context = self.decrypt_mfa_token(mfa_token)
        factor_type = options["factor_type"]
        base_url = await self._resolve_base_url(store_options)
        url = f"{base_url}/mfa/associate"

        # Map factor_type to Auth0 API parameters
        if factor_type == "otp":
            authenticator_type = "otp"
            oob_channels = None
        elif factor_type in ["sms", "voice", "email", "auth0"]:
            authenticator_type = "oob"
            oob_channels = factor_type
        else:
            raise MfaEnrollmentError(
                f"Unsupported factor_type: {factor_type}. Supported types: otp, sms, voice, email, auth0"
            )

        # Build API request body
        body: dict[str, Any] = {
            "authenticator_types": [authenticator_type]
        }

        if oob_channels:
            body["oob_channels"] = [oob_channels]

        if "phone_number" in options and options["phone_number"]:
            body["phone_number"] = options["phone_number"]

        if "email" in options and options["email"]:
            body["email"] = options["email"]

        try:
            async with self._get_http_client() as client:
                response = await client.post(
                    url,
                    json=body,
                    auth=BearerAuth(context.mfa_token),
                    headers={"Content-Type": "application/json"}
                )

                if response.status_code != 200:
                    error_data = self._parse_error_body(response)
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
                "Unexpected error enrolling authenticator"
            ) from e

    async def challenge_authenticator(
        self,
        options: dict[str, Any],
        store_options: Optional[dict[str, Any]] = None
    ) -> ChallengeResponse:
        """
        Initiates an MFA challenge for user verification.

        Args:
            options: Dict containing 'mfa_token', 'factor_type' (otp, sms, voice, email, auth0),
                and optionally 'authenticator_id'.
            store_options: Optional options passed to the State Store (e.g. request/response).

        Returns:
            ChallengeResponse with challenge details.

        Raises:
            MfaChallengeError: When the challenge fails.
        """
        mfa_token = options.get("mfa_token")
        if not mfa_token:
            raise MfaTokenInvalidError()
        context = self.decrypt_mfa_token(mfa_token)
        factor_type = options["factor_type"]
        base_url = await self._resolve_base_url(store_options)
        url = f"{base_url}/mfa/challenge"

        # Map factor_type to Auth0 API challenge_type
        if factor_type == "otp":
            challenge_type = "otp"
        elif factor_type in ["sms", "voice", "email", "auth0"]:
            challenge_type = "oob"
        else:
            raise MfaChallengeError(
                f"Unsupported factor_type: {factor_type}. Supported types: otp, sms, voice, email, auth0"
            )

        body: dict[str, Any] = {
            "mfa_token": context.mfa_token,
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "challenge_type": challenge_type
        }

        if "authenticator_id" in options and options["authenticator_id"]:
            body["authenticator_id"] = options["authenticator_id"]

        try:
            async with self._get_http_client() as client:
                response = await client.post(
                    url,
                    json=body,
                    headers={"Content-Type": "application/json"}
                )

                if response.status_code != 200:
                    error_data = self._parse_error_body(response)
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
                "Unexpected error challenging authenticator"
            ) from e

    async def verify(
        self,
        options: dict[str, Any],
        store_options: Optional[dict[str, Any]] = None,
    ) -> MfaVerifyResponse:
        """
        Verifies an MFA code and completes authentication.

        Supports OTP, OOB (with binding code), and recovery code verification.

        If Auth0 returns 'mfa_required' again (chained MFA), raises MfaRequiredError
        with a raw mfa_token. The framework SDK (e.g. auth0-fastapi) is responsible
        for encrypting the token before returning it to the client.

        Args:
            options: Dict containing 'mfa_token' and one of:
                - 'otp': OTP code
                - 'oob_code' + 'binding_code': OOB verification
                - 'recovery_code': Recovery code
                - 'persist': bool (optional, default=False) - Persist tokens to state store
                - 'audience': str (optional, required if persist=True) - Audience for token_set
                - 'scope': str (optional) - Scope for token_set
            store_options: Optional options passed to the State Store (e.g. request/response).

        Returns:
            MfaVerifyResponse with access_token, token_type, etc.

        Raises:
            MfaVerifyError: When verification fails.
            MfaRequiredError: When chained MFA is required.
        """
        mfa_token = options.get("mfa_token")
        if not mfa_token:
            raise MfaTokenInvalidError()
        context = self.decrypt_mfa_token(mfa_token)

        body: dict[str, Any] = {
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "mfa_token": context.mfa_token
        }

        if "otp" in options:
            body["grant_type"] = "http://auth0.com/oauth/grant-type/mfa-otp"
            body["otp"] = options["otp"]
        elif "oob_code" in options:
            body["grant_type"] = "http://auth0.com/oauth/grant-type/mfa-oob"
            body["oob_code"] = options["oob_code"]
            if options.get("binding_code"):
                body["binding_code"] = options["binding_code"]
        elif "recovery_code" in options:
            body["grant_type"] = "http://auth0.com/oauth/grant-type/mfa-recovery-code"
            body["recovery_code"] = options["recovery_code"]
        else:
            raise MfaVerifyError(
                "No verification credential provided (otp, oob_code, or recovery_code)"
            )

        try:
            base_url = await self._resolve_base_url(store_options)
            token_endpoint = f"{base_url}/oauth/token"

            async with self._get_http_client() as client:
                response = await client.post(
                    token_endpoint,
                    data=body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )

                if response.status_code != 200:
                    error_data = self._parse_error_body(response)

                    if error_data.get("error") == "mfa_required":
                        # Chained MFA: re-encrypt the new token with the original
                        # audience/scope from the incoming context before raising.
                        await self._raise_mfa_required(
                            error_data,
                            audience=context.audience,
                            scope=context.scope,
                            default_description="Additional MFA factor required",
                        )

                    raise MfaVerifyError(
                        error_data.get("error_description", "MFA verification failed"),
                        error_data
                    )

                token_response = response.json()
                verify_response = MfaVerifyResponse(**token_response)

                # Clear the in-progress MFA state after successful verification.
                if self._state_store:
                    await self._state_store.delete(MFA_PENDING_IDENTIFIER, store_options)

                if options.get("persist") and self._state_store:
                    await self._persist_mfa_tokens(
                        verify_response=verify_response,
                        options={**options, "audience": options.get("audience") or context.audience, "scope": options.get("scope") or context.scope},
                        store_options=store_options
                    )

                return verify_response

        except (MfaVerifyError, MfaRequiredError):
            raise
        except Exception as e:
            raise MfaVerifyError(
                "Unexpected error during MFA verification"
            ) from e

    async def _persist_mfa_tokens(
        self,
        verify_response: MfaVerifyResponse,
        options: dict[str, Any],
        store_options: Optional[dict[str, Any]] = None
    ) -> None:
        """
        Persist MFA verification tokens to the state store.

        Updates the session with the new access_token and id_token from MFA verification.

        Args:
            verify_response: The response from verify() containing tokens
            options: Dict containing:
                - 'audience': str - Audience for token_set
                - 'scope': str (optional) - Scope for token_set
            store_options: Optional options passed to the State Store (e.g. request/response).
        """
        audience = options.get("audience")
        scope = options.get("scope")

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
            expires_at = int(time.time()) + verify_response.expires_in

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
                existing_state.model_dump(),
                options=store_options
            )

        except MfaVerifyError:
            raise
        except Exception as e:
            raise MfaVerifyError(
                "Failed to persist MFA tokens to state store"
            ) from e
