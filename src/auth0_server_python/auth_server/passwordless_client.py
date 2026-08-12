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

if TYPE_CHECKING:  # avoid a circular import at runtime
    from auth0_server_python.auth_server.server_client import ServerClient

PASSWORDLESS_OTP_GRANT_TYPE = "http://auth0.com/oauth/grant-type/passwordless/otp"
# Email flows request the `email` scope; SMS has no email claim to satisfy.
DEFAULT_PASSWORDLESS_EMAIL_SCOPE = "openid profile email"
DEFAULT_PASSWORDLESS_SMS_SCOPE = "openid profile"
# Header Auth0 reads for the real end-user IP (confidential clients with
# "Trust Token Endpoint IP Header" enabled).
FORWARDED_FOR_HEADER = "auth0-forwarded-for"
# Cap on a non-JSON error body retained as an exception cause.
_RAW_ERROR_BODY_LIMIT = 2048


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
            InvalidArgumentError: When ``options`` is not a recognized type, or
                caller ``auth_params`` contains an SDK-owned or unrecognized key.
            MissingRequiredArgumentError: When a magic link is requested but no
                ``redirect_uri`` is configured on the client, or ``store_options``
                is not provided.
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

        magic_link_transaction = None
        if is_magic_link:
            auth_params, magic_link_transaction = self._prepare_magic_link_start(
                options, origin_domain, store_options
            )
            body["authParams"] = auth_params
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
            default_code = (
                PasswordlessErrorCode.TOO_MANY_REQUESTS
                if response.status_code == 429
                else PasswordlessErrorCode.START_FAILED
            )
            raise PasswordlessStartError(
                error_body.get("error", default_code),
                error_body.get("error_description", "Failed to start passwordless flow"),
                error_body if error_body else self._raw_text(response),
                self._retry_after(response),
            )

        if magic_link_transaction is not None:
            tx_key, transaction_data = magic_link_transaction
            await client._transaction_store.set(
                tx_key,
                transaction_data,
                remove_if_expires=True,
                options=store_options,
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
            MfaRequiredError: When Auth0 requires MFA before completing login.
            ApiError: When fetching the JWKS used to verify the ID token fails.
            SessionExpiredError: When the token's session-expiry ceiling is
                already in the past.
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
        # A caller-supplied scope replaces the default wholesale, so `openid`
        # is re-injected the same way as the magic-link path: without it Auth0
        # returns no ID token and verification fails with no claims to persist.
        scope = self._ensure_openid_scope(options.scope or default_scope)
        body: dict[str, Any] = {
            "grant_type": PASSWORDLESS_OTP_GRANT_TYPE,
            "client_id": client._client_id,
            "client_secret": client._client_secret,
            "realm": options.connection,
            "username": options.username,
            "otp": options.verification_code,
            "scope": scope,
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
            if error_body.get("error") == "mfa_required" and error_body.get("mfa_token"):
                await client._mfa_client._raise_mfa_required(
                    error_body,
                    audience=options.audience or client.DEFAULT_AUDIENCE_STATE_KEY,
                    scope=scope,
                    default_description="Multifactor authentication required",
                    store_options=store_options,
                )
            default_code = (
                PasswordlessErrorCode.TOO_MANY_REQUESTS
                if response.status_code == 429
                else PasswordlessErrorCode.INVALID_GRANT
            )
            raise PasswordlessVerifyError(
                error_body.get("error", default_code),
                error_body.get("error_description", "Passwordless verification failed"),
                error_body if error_body else self._raw_text(response),
                self._retry_after(response),
            )

        token_response = response.json()

        user_claims, id_token_claims = await self._verify_id_token(
            token_response, origin_domain, origin_issuer, metadata
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

    def _prepare_magic_link_start(
        self,
        options: StartPasswordlessEmailOptions,
        origin_domain: str,
        store_options: Optional[dict[str, Any]],
    ) -> tuple[dict[str, Any], tuple[str, TransactionData]]:
        """
        Build the magic-link ``authParams`` and the transaction to persist.

        The SDK owns ``redirect_uri`` / ``response_type`` / ``state``; caller
        ``auth_params`` may only contribute non-reserved passthrough keys.
        Persisting the transaction is the caller's job, deferred until after
        ``POST /passwordless/start`` succeeds — a failed start must not leave a
        transaction (and its cookie) behind.

        Raises:
            MissingRequiredArgumentError: When no ``redirect_uri`` is configured
                on the client, or ``store_options`` is not provided.
        """
        client = self._client

        redirect_uri = client._redirect_uri
        if not redirect_uri:
            raise MissingRequiredArgumentError("redirect_uri")

        auth_params = self._sanitize_caller_auth_params(options.auth_params)

        if store_options is None:
            raise MissingRequiredArgumentError("store_options")

        # Auth0 echoes `state` back unvalidated on this flow — it does not
        # compare it server-side, and the clicked link's query string can
        # overwrite whatever was originally stored. This SDK's single-use,
        # state-keyed transaction plus the exact-match, SDK-owned
        # `redirect_uri` is therefore the *only* CSRF/authorization-code-
        # interception control on magic link; the server provides none.
        # Never make `state`/`redirect_uri` caller-overridable.
        state = PKCE.generate_random_string(32)
        auth_params["redirect_uri"] = redirect_uri
        auth_params["response_type"] = "code"
        auth_params["state"] = state
        auth_params.setdefault("scope", DEFAULT_PASSWORDLESS_EMAIL_SCOPE)
        # A caller-supplied scope replaces the default wholesale, so `openid`
        # is re-injected rather than trusted: without it Auth0 returns no ID
        # token and the callback never demands one, leaving a session with no
        # signature-verified claims.
        auth_params["scope"] = self._ensure_openid_scope(auth_params["scope"])

        transaction_data = TransactionData(
            code_verifier=None,
            audience=auth_params.get("audience"),
            redirect_uri=redirect_uri,
            domain=origin_domain,
        )
        tx_key = f"{client._transaction_identifier}:{state}"

        return auth_params, (tx_key, transaction_data)

    @staticmethod
    def _ensure_openid_scope(scope: str) -> str:
        """Prepend ``openid`` to a scope string that omits it, preserving order."""
        scopes = scope.split()
        if "openid" in scopes:
            return scope
        return " ".join(["openid", *scopes])

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
            raise PasswordlessVerifyError(
                PasswordlessErrorCode.INVALID_ISSUER,
                "ID token issuer mismatch. Ensure your Auth0 domain is configured correctly.",
                IssuerValidationError(
                    "ID token issuer mismatch. Ensure your Auth0 domain is configured correctly."
                ),
            )

        return UserClaims.model_validate(claims), claims

    @staticmethod
    def _safe_json(response) -> dict[str, Any]:
        """Parse a response body as JSON, returning {} on failure."""
        try:
            data = response.json()
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    @staticmethod
    def _retry_after(response) -> Optional[int]:
        """
        Return the ``Retry-After`` delay in seconds, or None when absent or
        not an integer count (the HTTP-date form is not interpreted).
        """
        raw = response.headers.get("Retry-After")
        if raw is None:
            return None
        try:
            return int(raw)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _raw_text(response) -> Optional[str]:
        """
        Return the response body text, truncated, for diagnosing a non-JSON
        error body.

        Capped because the body may be an HTML error page, WAF block page, or
        proxy dump: it is attached as the exception ``cause`` and reaches any
        logger that serializes it, and httpx applies no response-size limit.
        """
        try:
            return response.text[:_RAW_ERROR_BODY_LIMIT]
        except Exception:
            return None
