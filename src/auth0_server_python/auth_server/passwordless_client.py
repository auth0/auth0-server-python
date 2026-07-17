"""
Passwordless Client for auth0-server-python SDK.

Implements embedded passwordless login (Legacy Passwordless connections) for a
confidential (Regular Web App) client:

* Email OTP / SMS OTP — ``start()`` sends a code, ``verify()`` exchanges it for
  tokens via the passwordless-OTP grant and establishes a server-side session.
* Magic link — ``start(send="link")`` emails a one-click link; completion is
  handled by the standard callback (``ServerClient.complete_interactive_login``),
  not by ``verify()``.

Tokens never leave the server; the browser holds only the opaque session
reference (RWA / BFF posture).
"""

from typing import TYPE_CHECKING, Any, Optional

import jwt

from auth0_server_python.auth_types import (
    PASSWORDLESS_ALLOWED_AUTH_PARAMS,
    PASSWORDLESS_RESERVED_AUTH_PARAMS,
    PasswordlessStartResult,
    StartPasswordlessEmailOptions,
    StartPasswordlessOptions,
    StartPasswordlessSmsOptions,
    TransactionData,
    UserClaims,
    VerifyPasswordlessOtpOptions,
)
from auth0_server_python.error import (
    InvalidArgumentError,
    IssuerValidationError,
    MissingRequiredArgumentError,
    PasswordlessErrorCode,
    PasswordlessStartError,
    PasswordlessVerifyError,
)
from auth0_server_python.utils import PKCE
from auth0_server_python.utils.helpers import validate_org_claims

if TYPE_CHECKING:  # avoid a circular import at runtime
    from auth0_server_python.auth_server.server_client import ServerClient

PASSWORDLESS_OTP_GRANT_TYPE = "http://auth0.com/oauth/grant-type/passwordless/otp"
# Email flows request the `email` scope; SMS has no email claim to satisfy.
DEFAULT_PASSWORDLESS_EMAIL_SCOPE = "openid profile email"
DEFAULT_PASSWORDLESS_SMS_SCOPE = "openid profile"
# Header Auth0 reads for the real end-user IP (confidential clients with
# "Trust Token Endpoint IP Header" enabled).
FORWARDED_FOR_HEADER = "auth0-forwarded-for"


class PasswordlessClient:
    """
    Client for Auth0 embedded passwordless operations.

    Composes the parent :class:`ServerClient` to reuse domain resolution, OIDC
    discovery, JWKS/ID-token verification, and session persistence rather than
    duplicating that security-critical logic.
    """

    def __init__(self, server_client: "ServerClient"):
        self._client = server_client

    # ------------------------------------------------------------------ start

    async def start(
        self,
        options: StartPasswordlessOptions,
        store_options: Optional[dict[str, Any]] = None,
    ) -> PasswordlessStartResult:
        """
        Start a passwordless flow by sending an OTP code or a magic link.

        Args:
            options: ``StartPasswordlessEmailOptions`` or
                ``StartPasswordlessSmsOptions``.
            store_options: Options passed to the transaction store (e.g.
                request/response) — required for the magic-link flow so the
                transaction cookie can be written.

        Returns:
            PasswordlessStartResult with Auth0's start response payload.

        Raises:
            PasswordlessStartError: When ``POST /passwordless/start`` fails.
            InvalidArgumentError: When caller ``auth_params`` attempts to
                override an SDK-owned parameter.
            MissingRequiredArgumentError: When a magic link is requested but no
                ``redirect_uri`` is configured on the client.
        """
        client = self._client
        origin_domain = await client._resolve_current_domain(store_options)

        body: dict[str, Any] = {
            "client_id": client._client_id,
            "client_secret": client._client_secret,
            "connection": options.connection,
        }

        if isinstance(options, StartPasswordlessEmailOptions):
            body["email"] = options.email
            body["send"] = options.send
        elif isinstance(options, StartPasswordlessSmsOptions):
            body["phone_number"] = options.phone_number
        else:
            raise InvalidArgumentError(
                "options",
                "options must be StartPasswordlessEmailOptions or StartPasswordlessSmsOptions",
            )

        if options.captcha:
            body["captcha"] = options.captcha

        is_magic_link = (
            isinstance(options, StartPasswordlessEmailOptions) and options.send == "link"
        )

        if is_magic_link:
            body["authParams"] = await self._build_magic_link_auth_params(
                options, origin_domain, store_options
            )
        elif options.auth_params:
            # OTP flows: forward safe passthrough params only.
            body["authParams"] = self._sanitize_caller_auth_params(options.auth_params)

        headers = {"Content-Type": "application/json"}
        if options.language:
            headers["x-request-language"] = options.language
        if options.client_ip:
            headers[FORWARDED_FOR_HEADER] = options.client_ip

        base_url = client._normalize_url(origin_domain)
        url = f"{base_url}/passwordless/start"

        try:
            async with client._get_http_client() as http:
                response = await http.post(url, json=body, headers=headers)
        except Exception as e:
            raise PasswordlessStartError(
                PasswordlessErrorCode.START_FAILED,
                f"Unexpected error during passwordless start: {str(e)}",
                e,
            )

        if response.status_code not in (200, 201):
            error_body = self._safe_json(response)
            raise PasswordlessStartError(
                error_body.get("error", PasswordlessErrorCode.START_FAILED),
                error_body.get("error_description", "Failed to start passwordless flow"),
                error_body,
            )

        return PasswordlessStartResult(**self._safe_json(response))

    # ----------------------------------------------------------------- verify

    async def verify(
        self,
        options: VerifyPasswordlessOtpOptions,
        store_options: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """
        Verify a passwordless OTP and establish a server-side session.

        Only for the OTP flows (email/SMS code). Magic link completes via the
        standard callback handler, not here.

        Args:
            options: VerifyPasswordlessOtpOptions.
            store_options: Options passed to the state store (e.g.
                request/response) so the session can be written.

        Returns:
            Dict containing ``state_data`` for the established session.

        Raises:
            PasswordlessVerifyError: When token exchange or ID-token
                verification fails.
        """
        client = self._client
        origin_domain = await client._resolve_current_domain(store_options)

        try:
            metadata = await client._get_oidc_metadata_cached(origin_domain)
        except Exception as e:
            raise PasswordlessVerifyError(
                PasswordlessErrorCode.DISCOVERY_ERROR,
                "Failed to fetch authorization server metadata",
                e,
            )

        token_endpoint = metadata["token_endpoint"]
        origin_issuer = metadata.get("issuer")

        default_scope = (
            DEFAULT_PASSWORDLESS_EMAIL_SCOPE
            if options.connection == "email"
            else DEFAULT_PASSWORDLESS_SMS_SCOPE
        )
        body: dict[str, Any] = {
            "grant_type": PASSWORDLESS_OTP_GRANT_TYPE,
            "client_id": client._client_id,
            "client_secret": client._client_secret,
            "realm": options.connection,
            "username": options.username,
            "otp": options.verification_code,
            "scope": options.scope or default_scope,
        }
        if options.audience:
            body["audience"] = options.audience

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if options.client_ip:
            headers[FORWARDED_FOR_HEADER] = options.client_ip

        try:
            async with client._get_http_client() as http:
                response = await http.post(
                    token_endpoint,
                    data=body,
                    headers=headers,
                )
        except Exception as e:
            raise PasswordlessVerifyError(
                PasswordlessErrorCode.VERIFY_FAILED,
                f"Unexpected error during passwordless verify: {str(e)}",
                e,
            )

        if response.status_code != 200:
            error_body = self._safe_json(response)
            raise PasswordlessVerifyError(
                error_body.get("error", PasswordlessErrorCode.INVALID_GRANT),
                error_body.get("error_description", "Passwordless verification failed"),
                error_body,
            )

        token_response = response.json()

        user_claims, id_token_claims = await self._verify_id_token(
            token_response, origin_domain, origin_issuer, metadata, options.organization
        )

        state_data = await client._persist_session_from_token_response(
            token_response=token_response,
            user_claims=user_claims,
            origin_domain=origin_domain,
            audience=options.audience,
            session_expires_at=user_claims.session_expiry,
            issued_at=id_token_claims.get("iat"),
            id_token_claims=id_token_claims,
            store_options=store_options,
        )

        return {"state_data": state_data.model_dump()}

    # ------------------------------------------------------------- internals

    async def _build_magic_link_auth_params(
        self,
        options: StartPasswordlessEmailOptions,
        origin_domain: str,
        store_options: Optional[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Build the magic-link ``authParams`` and persist the transaction.

        The SDK owns ``redirect_uri`` / ``response_type`` / ``state``; caller
        ``auth_params`` may only contribute non-reserved passthrough keys.
        """
        client = self._client

        redirect_uri = client._redirect_uri
        if not redirect_uri:
            raise MissingRequiredArgumentError("redirect_uri")

        auth_params = self._sanitize_caller_auth_params(options.auth_params)

        state = PKCE.generate_random_string(32)
        auth_params["redirect_uri"] = redirect_uri
        auth_params["response_type"] = "code"
        auth_params["state"] = state
        # Magic link is email-only, so the email scope is always appropriate.
        auth_params.setdefault("scope", DEFAULT_PASSWORDLESS_EMAIL_SCOPE)
        if options.organization:
            auth_params["organization"] = options.organization

        # Magic link uses a plain authorization-code exchange (no PKCE), so the
        # transaction stores no code_verifier. Single-use is enforced by
        # transaction deletion on the callback; remove_if_expires signals the
        # store to drop the transaction once expired. Its effective lifetime is
        # the store's configured duration, not a fixed value set here.
        transaction_data = TransactionData(
            code_verifier=None,
            audience=auth_params.get("audience"),
            redirect_uri=redirect_uri,
            domain=origin_domain,
            organization=options.organization,
        )
        await client._transaction_store.set(
            f"{client._transaction_identifier}:{state}",
            transaction_data,
            remove_if_expires=True,
            options=store_options,
        )

        return auth_params

    def _sanitize_caller_auth_params(self, auth_params: Optional[dict[str, Any]]) -> dict[str, Any]:
        """
        Copy caller-supplied auth params, forwarding only allowlisted keys.

        Enforced as an allowlist (Global §3): a key outside
        ``PASSWORDLESS_ALLOWED_AUTH_PARAMS`` is rejected. SDK-owned keys get a
        precise "set by the SDK" message; anything else is reported as
        unsupported so a new authorize param cannot pass through silently.

        Raises:
            InvalidArgumentError: When a reserved or unrecognized param is present.
        """
        if not auth_params:
            return {}
        for key in auth_params:
            if key in PASSWORDLESS_RESERVED_AUTH_PARAMS:
                raise InvalidArgumentError(
                    "auth_params",
                    f"'{key}' is set by the SDK and cannot be overridden",
                )
            if key not in PASSWORDLESS_ALLOWED_AUTH_PARAMS:
                raise InvalidArgumentError(
                    "auth_params",
                    f"'{key}' is not an allowed passthrough auth parameter",
                )
        return dict(auth_params)

    async def _verify_id_token(
        self,
        token_response: dict[str, Any],
        origin_domain: str,
        origin_issuer: Optional[str],
        metadata: dict[str, Any],
        expected_org: Optional[str],
    ) -> tuple[UserClaims, dict[str, Any]]:
        """Verify the ID token from the OTP exchange and return its claims."""
        client = self._client
        id_token = token_response.get("id_token")
        if not id_token:
            raise PasswordlessVerifyError(
                PasswordlessErrorCode.VERIFY_FAILED,
                "Token response did not include an ID token; ensure 'openid' scope is requested",
            )

        jwks = await client._get_jwks_cached(origin_domain, metadata)

        try:
            claims = await client._verify_and_decode_jwt(id_token, jwks, audience=client._client_id)
        except ValueError as e:
            raise PasswordlessVerifyError(PasswordlessErrorCode.VERIFY_FAILED, str(e), e)
        except jwt.InvalidAudienceError as e:
            raise PasswordlessVerifyError(
                PasswordlessErrorCode.INVALID_AUDIENCE,
                "ID token audience mismatch. Ensure your client_id is configured correctly.",
                e,
            )
        except jwt.InvalidTokenError as e:
            # Covers expired signature, bad signature, and other token defects.
            raise PasswordlessVerifyError(
                PasswordlessErrorCode.VERIFY_FAILED,
                f"ID token verification failed: {str(e)}",
                e,
            )

        token_issuer = claims.get("iss", "")
        if client._normalize_url(token_issuer) != client._normalize_url(origin_issuer):
            raise IssuerValidationError(
                "ID token issuer mismatch. Ensure your Auth0 domain is configured correctly."
            )

        if expected_org:
            validate_org_claims(claims, expected_org)

        return UserClaims.model_validate(claims), claims

    @staticmethod
    def _safe_json(response) -> dict[str, Any]:
        """Parse a response body as JSON, returning {} on failure."""
        try:
            data = response.json()
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}
