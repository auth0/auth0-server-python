"""
Anonymous Sessions client for auth0-server-python SDK.
Handles pre-login anon@ identity operations against the Auth0 anonymous session API.
"""

import json
import time
from typing import Any, Optional

import httpx
from pydantic import ValidationError

from auth0_server_python.auth_schemes.bearer_auth import BearerAuth
from auth0_server_python.auth_types import (
    AnonymousSession,
    AnonymousSessionContext,
    AnonymousSessionIntrospection,
    AnonymousTokenResponse,
)
from auth0_server_python.encryption.encrypt import decrypt, encrypt
from auth0_server_python.error import (
    AnonymousApiError,
    AnonymousClientNotEnabledError,
    AnonymousClientNotSupportedError,
    AnonymousFeatureNotEnabledError,
    AnonymousLogoutError,
    AnonymousResourceServerError,
    AnonymousScopeError,
    AnonymousSessionCreateError,
    AnonymousSessionIntrospectError,
    AnonymousTokenError,
    ConfigurationError,
    DomainResolverError,
    _AnonymousSessionExpired,
)
from auth0_server_python.utils.helpers import (
    build_domain_resolver_context,
    validate_resolved_domain_value,
)

# Salt only — isolation comes from the store instance, not this key.
ANON_IDENTIFIER = "_a0_anon"
ANON_TOKEN_SALT = "anon_session"

_METADATA_MAX_BYTES = 1024
_DANGEROUS_METADATA_KEYS = frozenset({"__proto__", "constructor", "prototype"})


class AnonymousClient:
    """
    Client for Auth0 anonymous session operations.

    Requires its own store instance, distinct from ServerClient's state_store —
    a shared identifier isn't sufficient isolation on the default auth0-fastapi
    store. Never accepts a dpop_key: DPoP-mandated clients are structurally
    excluded from anonymous sessions.
    """

    def __init__(
        self,
        domain,
        client_id: str,
        client_secret: str,
        secret: str,
        anonymous_store=None,
        default_audience: Optional[str] = None,
        default_scope: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
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
        self._anonymous_store = anonymous_store
        self._default_audience = default_audience
        self._default_scope = default_scope
        self._headers = headers or {}

    def _get_http_client(self, **kwargs) -> httpx.AsyncClient:
        """Return an httpx.AsyncClient with default headers injected."""
        headers = {**kwargs.pop("headers", {}), **self._headers}
        return httpx.AsyncClient(headers=headers, **kwargs)

    def _require_store(self) -> None:
        """Fail closed before any write when no anonymous store is configured."""
        if self._anonymous_store is None:
            raise ConfigurationError(
                "AnonymousClient requires its own anonymous_store, distinct from "
                "ServerClient's state_store. Writing anonymous state into the same "
                "store instance can silently overwrite the authenticated session."
            )

    async def _resolve_domain(self, store_options: Optional[dict[str, Any]] = None) -> str:
        """Resolve domain from resolver function or return static domain."""
        if self._domain_resolver:
            context = build_domain_resolver_context(store_options)
            try:
                resolved = await self._domain_resolver(context)
                return validate_resolved_domain_value(resolved)
            except DomainResolverError:
                raise
            except Exception as e:
                raise DomainResolverError(
                    f"Domain resolver function raised an exception: {str(e)}",
                    original_error=e,
                )
        return self._domain

    @staticmethod
    def _normalize_url(value: Optional[str]) -> Optional[str]:
        """Normalize a domain-like value for comparison (scheme + case + trailing slash)."""
        if not value:
            return value
        value = value.lower()
        if value.startswith("https://"):
            pass
        elif value.startswith("http://"):
            value = value.replace("http://", "https://")
        else:
            value = f"https://{value}"
        return value.rstrip("/")

    # ============================================================================
    # ERROR HANDLING
    # ============================================================================

    @staticmethod
    def _parse_anonymous_error_body(response: httpx.Response) -> dict[str, Any]:
        """Parse an error response body as JSON. Kept private to this module —
        do not merge with MfaClient._parse_error_body."""
        try:
            data = response.json()
        except (json.JSONDecodeError, ValueError):
            data = None
        if not isinstance(data, dict):
            return {
                "error_description": f"Request failed with status {response.status_code}",
            }
        return data

    def _map_anonymous_error(
        self,
        status_code: int,
        error_data: dict[str, Any],
        operation: str,
    ) -> Exception:
        """
        Single dispatcher from a server error response to a typed exception.

        Returns the exception instance (does not raise it) so every call site
        raises the same way: `raise self._map_anonymous_error(...)`.
        """
        code = error_data.get("error", "")
        description = error_data.get("error_description") or f"Anonymous {operation} failed"

        if code in ("session_expired", "invalid_session_token"):
            return _AnonymousSessionExpired(description)
        # Distinguishes DPoP-mandated clients from a plain client-not-enabled block.
        if status_code == 400 and "Proof-of-Possession" in description:
            return AnonymousClientNotSupportedError(description, error_data)
        if code == "feature_not_enabled":
            return AnonymousFeatureNotEnabledError(description, error_data)
        if code == "unauthorized_client":
            return AnonymousClientNotEnabledError(description, error_data)
        if code in ("invalid_target", "invalid_request"):
            return AnonymousResourceServerError(description, error_data)
        if code == "invalid_scope":
            return AnonymousScopeError(description, error_data)

        if operation == "create":
            return AnonymousSessionCreateError(description, cause=error_data)
        if operation == "token":
            return AnonymousTokenError(description, error_data)
        if operation == "logout":
            return AnonymousLogoutError(description, error_data)
        if operation == "introspect":
            return AnonymousSessionIntrospectError(description, error_data)
        return AnonymousApiError(code or "anonymous_error", description, error_data)

    # ============================================================================
    # METADATA VALIDATION
    # ============================================================================

    @staticmethod
    def _validate_metadata(metadata: Optional[dict[str, Any]]) -> None:
        """Client-side pre-flight so an oversized/invalid payload never reaches the network."""
        if metadata is None:
            return
        if not isinstance(metadata, dict):
            raise AnonymousSessionCreateError("metadata must be a JSON object", code="invalid_metadata")
        for key, value in metadata.items():
            if key in _DANGEROUS_METADATA_KEYS:
                raise AnonymousSessionCreateError(
                    f"metadata key '{key}' is not allowed", code="invalid_metadata"
                )
            if not isinstance(value, str):
                raise AnonymousSessionCreateError(
                    f"metadata value for key '{key}' must be a string", code="invalid_metadata"
                )
        size = len(json.dumps(metadata).encode("utf-8"))
        if size > _METADATA_MAX_BYTES:
            raise AnonymousSessionCreateError(
                "metadata exceeds the 1KB size limit", code="metadata_too_large"
            )

    # ============================================================================
    # ENCRYPTION
    # ============================================================================

    def _encrypt_context(self, context: AnonymousSessionContext) -> str:
        return encrypt(context.model_dump(), self._secret, ANON_TOKEN_SALT)

    def _decrypt_context(self, stored: Any) -> AnonymousSessionContext:
        """
        Decrypt and validate a stored anonymous session record.

        Mirrors MfaClient.decrypt_mfa_token's broad except: crypto-library and
        pydantic-validation failure modes are both "this record is unusable,"
        and both must convert to the same internal signal, never propagate an
        untyped exception to a caller.
        """
        try:
            encrypted = stored.get("context") if isinstance(stored, dict) else None
            if not encrypted:
                raise ValueError("Malformed anonymous session record")
            payload = decrypt(encrypted, self._secret, ANON_TOKEN_SALT)
            return AnonymousSessionContext(**payload)
        except Exception as e:
            raise _AnonymousSessionExpired(
                "Stored anonymous session token is invalid or corrupted."
            ) from e

    # ============================================================================
    # LOGIN INJECTION SUPPORT
    # ============================================================================

    async def get_session_token_for_injection(
        self, store_options: Optional[dict[str, Any]] = None
    ) -> Optional[str]:
        """
        Read the active anonymous session's raw token for injection into
        start_interactive_login(), without triggering the renewal ladder.

        Never raises: no configured store, no active session, or an
        undecryptable/corrupted record all return None — malformed linking
        state must deny the link, not abort the login.
        """
        if self._anonymous_store is None:
            return None
        try:
            stored = await self._anonymous_store.get(ANON_IDENTIFIER, options=store_options)
        except Exception:
            return None
        if not stored:
            return None
        try:
            context = self._decrypt_context(stored)
        except _AnonymousSessionExpired:
            return None
        return context.session_token

    # ============================================================================
    # SESSION CREATION
    # ============================================================================

    async def create_session(
        self,
        *,
        audience: Optional[str] = None,
        scope: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
        store_options: Optional[dict[str, Any]] = None,
    ) -> AnonymousSession:
        """
        Mint a fresh anon@<uuid> identity via POST /anonymous/token.

        Raises:
            ConfigurationError: No anonymous_store configured.
            AnonymousSessionCreateError: Local validation or server rejection.
        """
        self._require_store()
        self._validate_metadata(metadata)
        audience = audience or self._default_audience
        scope = scope or self._default_scope
        domain = await self._resolve_domain(store_options)
        return await self._create_session_at(
            domain, audience=audience, scope=scope, metadata=metadata, store_options=store_options
        )

    async def _create_session_at(
        self,
        domain: str,
        *,
        audience: Optional[str],
        scope: Optional[str],
        metadata: Optional[dict[str, Any]],
        store_options: Optional[dict[str, Any]],
    ) -> AnonymousSession:
        """Shared create-mode HTTP call, used by create_session() and every renewal-ladder fallback."""
        base_url = f"https://{domain}"
        body: dict[str, Any] = {"client_id": self._client_id}
        if self._client_secret:
            body["client_secret"] = self._client_secret
        if audience:
            body["audience"] = audience
        if scope:
            body["scope"] = scope
        if metadata:
            body["metadata"] = metadata

        async with self._get_http_client() as client:
            try:
                response = await client.post(f"{base_url}/anonymous/token", json=body)
            except httpx.HTTPError as e:
                raise AnonymousSessionCreateError(
                    "Failed to reach the anonymous token endpoint"
                ) from e

            if response.status_code != 200:
                error_data = self._parse_anonymous_error_body(response)
                mapped = self._map_anonymous_error(response.status_code, error_data, "create")
                if isinstance(mapped, _AnonymousSessionExpired):
                    # Internal-only type must never escape.
                    raise AnonymousSessionCreateError(str(mapped))
                raise mapped

            try:
                token_response = AnonymousTokenResponse.model_validate(response.json())
            except (json.JSONDecodeError, ValueError, ValidationError) as e:
                raise AnonymousSessionCreateError(
                    "Failed to parse anonymous token response"
                ) from e

        if not token_response.session_token or not token_response.sub or not token_response.session_id:
            raise AnonymousSessionCreateError("Anonymous token response missing required fields")

        now = int(time.time())
        context = AnonymousSessionContext(
            session_token=token_response.session_token,
            sub=token_response.sub,
            session_id=token_response.session_id,
            access_token=token_response.access_token,
            expires_at=now + token_response.expires_in,
            session_expires_at=(
                now + token_response.session_expires_in
                if token_response.session_expires_in
                else None
            ),
            metadata=metadata,
            created_at=now,
            domain=domain,
            audience=audience,
            scope=scope,
        )
        await self._anonymous_store.set(
            ANON_IDENTIFIER,
            {"context": self._encrypt_context(context)},
            options=store_options,
        )
        return AnonymousSession(
            sub=context.sub,
            session_id=context.session_id,
            access_token=context.access_token,
            expires_at=context.expires_at,
            session_expires_at=context.session_expires_at,
            metadata=context.metadata,
            is_new=True,
        )

    # ============================================================================
    # TOKEN RENEWAL LADDER
    # ============================================================================

    async def get_token(
        self, store_options: Optional[dict[str, Any]] = None
    ) -> AnonymousSession:
        """
        Return a valid anonymous access token, renewing or re-minting as needed.

        1. Cached access token still fresh -> return it.
        2. Expired -> re-mint with the session token (never a refresh-token grant).
        3. Session token also expired/invalid, corrupted, or minted for a
           different tenant (MCD) -> silently create a brand-new session, once.
        4. Any other error -> raise. No swallow, no auto-retry beyond step 3.

        Raises:
            ConfigurationError: No anonymous_store configured.
            AnonymousTokenError: No active session, or an unrecoverable failure.
        """
        self._require_store()
        stored = await self._anonymous_store.get(ANON_IDENTIFIER, options=store_options)
        if not stored:
            raise AnonymousTokenError("No active anonymous session. Call create_session() first.")

        try:
            context = self._decrypt_context(stored)
        except _AnonymousSessionExpired:
            # No audience/scope to recover — fall back to configured defaults.
            domain = await self._resolve_domain(store_options)
            return await self._create_session_at(
                domain,
                audience=self._default_audience,
                scope=self._default_scope,
                metadata=None,
                store_options=store_options,
            )

        if self._domain_resolver:
            current_domain = await self._resolve_domain(store_options)
            if context.domain and self._normalize_url(context.domain) != self._normalize_url(
                current_domain
            ):
                # Cross-tenant reuse must be structurally impossible — discard
                # and mint fresh under the current tenant instead.
                return await self._create_session_at(
                    current_domain,
                    audience=context.audience,
                    scope=context.scope,
                    metadata=None,
                    store_options=store_options,
                )

        now = int(time.time())
        if context.expires_at > now:
            return AnonymousSession(
                sub=context.sub,
                session_id=context.session_id,
                access_token=context.access_token,
                expires_at=context.expires_at,
                session_expires_at=context.session_expires_at,
                metadata=context.metadata,
                is_new=False,
            )

        return await self._remint(context, store_options)

    async def _remint(
        self, context: AnonymousSessionContext, store_options: Optional[dict[str, Any]]
    ) -> AnonymousSession:
        """Re-mint an access token using the stored session token, with a retry-once fallback."""
        domain = context.domain or await self._resolve_domain(store_options)
        base_url = f"https://{domain}"
        body: dict[str, Any] = {"client_id": self._client_id, "session_token": context.session_token}
        if self._client_secret:
            body["client_secret"] = self._client_secret

        async with self._get_http_client() as client:
            try:
                response = await client.post(f"{base_url}/anonymous/token", json=body)
            except httpx.HTTPError as e:
                raise AnonymousTokenError("Failed to reach the anonymous token endpoint") from e

            if response.status_code != 200:
                error_data = self._parse_anonymous_error_body(response)
                mapped = self._map_anonymous_error(response.status_code, error_data, "token")
                if isinstance(mapped, _AnonymousSessionExpired):
                    # Retry-once: exactly one follow-up create call, never a loop.
                    return await self._create_session_at(
                        domain,
                        audience=context.audience,
                        scope=context.scope,
                        metadata=None,
                        store_options=store_options,
                    )
                raise mapped

            try:
                token_response = AnonymousTokenResponse.model_validate(response.json())
            except (json.JSONDecodeError, ValueError, ValidationError) as e:
                raise AnonymousTokenError("Failed to parse anonymous token response") from e

        now = int(time.time())
        new_context = AnonymousSessionContext(
            # Rewrite when a fresh session_token is present, else keep the old one.
            session_token=token_response.session_token or context.session_token,
            sub=token_response.sub or context.sub,
            session_id=token_response.session_id or context.session_id,
            access_token=token_response.access_token,
            expires_at=now + token_response.expires_in,
            session_expires_at=(
                now + token_response.session_expires_in
                if token_response.session_expires_in
                else context.session_expires_at
            ),
            metadata=context.metadata,
            created_at=context.created_at,
            domain=domain,
            audience=context.audience,
            scope=context.scope,
        )
        await self._anonymous_store.set(
            ANON_IDENTIFIER,
            {"context": self._encrypt_context(new_context)},
            options=store_options,
        )
        return AnonymousSession(
            sub=new_context.sub,
            session_id=new_context.session_id,
            access_token=new_context.access_token,
            expires_at=new_context.expires_at,
            session_expires_at=new_context.session_expires_at,
            metadata=new_context.metadata,
            is_new=False,
        )

    # ============================================================================
    # INTROSPECTION
    # ============================================================================

    async def introspect(
        self, store_options: Optional[dict[str, Any]] = None
    ) -> AnonymousSessionIntrospection:
        """
        Read-only status check via GET /anonymous/userinfo.

        Never triggers the renewal ladder and never writes to the store —
        an unreadable stored context is a hard failure here, not a silent re-mint.

        Note: the platform's required auth mechanism for this endpoint is
        unspecified. Bearer access_token is the working assumption; confirm
        with the feature team before release.
        """
        self._require_store()
        stored = await self._anonymous_store.get(ANON_IDENTIFIER, options=store_options)
        if not stored:
            raise AnonymousSessionIntrospectError("No active anonymous session to introspect.")

        try:
            context = self._decrypt_context(stored)
        except _AnonymousSessionExpired as e:
            raise AnonymousSessionIntrospectError(
                "Stored anonymous session is invalid or corrupted."
            ) from e

        domain = context.domain or await self._resolve_domain(store_options)
        base_url = f"https://{domain}"

        async with self._get_http_client() as client:
            try:
                response = await client.get(
                    f"{base_url}/anonymous/userinfo",
                    auth=BearerAuth(context.access_token),
                )
            except httpx.HTTPError as e:
                raise AnonymousSessionIntrospectError(
                    "Failed to reach the anonymous userinfo endpoint"
                ) from e

            if response.status_code != 200:
                error_data = self._parse_anonymous_error_body(response)
                mapped = self._map_anonymous_error(response.status_code, error_data, "introspect")
                if isinstance(mapped, _AnonymousSessionExpired):
                    raise AnonymousSessionIntrospectError(str(mapped))
                raise mapped

            try:
                return AnonymousSessionIntrospection.model_validate(response.json())
            except (json.JSONDecodeError, ValueError, ValidationError) as e:
                raise AnonymousSessionIntrospectError(
                    "Failed to parse anonymous introspection response"
                ) from e

    # ============================================================================
    # LOGOUT
    # ============================================================================

    async def logout(self, store_options: Optional[dict[str, Any]] = None) -> None:
        """
        Clear the locally-held anonymous session.

        No server-side revocation exists — access tokens already issued remain
        valid until natural expiry. The remote POST below is best-effort only;
        the local store clear is what actually ends the session from this SDK's
        perspective.
        """
        self._require_store()
        stored = await self._anonymous_store.get(ANON_IDENTIFIER, options=store_options)
        if not stored:
            return

        try:
            context = self._decrypt_context(stored)
        except _AnonymousSessionExpired:
            context = None

        if context is not None:
            domain = context.domain or await self._resolve_domain(store_options)
            base_url = f"https://{domain}"
            body: dict[str, Any] = {
                "client_id": self._client_id,
                "session_token": context.session_token,
            }
            if self._client_secret:
                body["client_secret"] = self._client_secret
            try:
                async with self._get_http_client() as client:
                    await client.post(f"{base_url}/anonymous/logout", json=body)
            except httpx.HTTPError:
                pass

        await self._anonymous_store.delete(ANON_IDENTIFIER, options=store_options)
