"""
Anonymous Sessions client for auth0-server-python SDK.
Handles pre-login anon@ identity operations against the Auth0 anonymous session API.
"""

import json
import time
from typing import Any, Optional, Union

import httpx
from pydantic import ValidationError

from auth0_server_python.auth_schemes.bearer_auth import BearerAuth
from auth0_server_python.auth_types import (
    AnonymousSession,
    AnonymousSessionContext,
    AnonymousSessionIntrospection,
    AnonymousTokenResponse,
    CreateAnonymousSessionOptions,
)
from auth0_server_python.encryption.encrypt import decrypt, encrypt
from auth0_server_python.error import (
    AnonymousSessionApiError,
    AnonymousSessionClientNotEnabledError,
    AnonymousSessionClientNotSupportedError,
    AnonymousSessionCreateError,
    AnonymousSessionFeatureNotEnabledError,
    AnonymousSessionIntrospectError,
    AnonymousSessionLogoutError,
    AnonymousSessionResourceServerError,
    AnonymousSessionScopeError,
    AnonymousSessionTokenError,
    ConfigurationError,
    DomainResolverError,
    _AnonymousSessionExpired,
)
from auth0_server_python.utils.helpers import (
    build_domain_resolver_context,
    validate_resolved_domain_value,
)

ANON_IDENTIFIER = "_a0_anon"
ANON_TOKEN_SALT = "anon_session"

_METADATA_MAX_BYTES = 1024
_DANGEROUS_METADATA_KEYS = frozenset({"__proto__", "constructor", "prototype"})


class AnonymousClient:
    """
    Client for Auth0 anonymous session operations.

    Requires its own store instance, distinct from ServerClient's state_store.
    DPoP is not supported with Anonymous Sessions.
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
        """Return an httpx.AsyncClient with default headers injected.

        Args:
            **kwargs: Forwarded to httpx.AsyncClient.

        Returns:
            A configured httpx.AsyncClient.
        """
        headers = {**kwargs.pop("headers", {}), **self._headers}
        return httpx.AsyncClient(headers=headers, **kwargs)

    def _require_store(self) -> None:
        """Fail closed when no anonymous store is configured.

        Raises:
            ConfigurationError: No anonymous_store configured.
        """
        if self._anonymous_store is None:
            raise ConfigurationError(
                "AnonymousClient requires its own anonymous_store, distinct from "
                "ServerClient's state_store. Writing anonymous state into the same "
                "store instance can silently overwrite the authenticated session."
            )

    async def _resolve_domain(self, store_options: Optional[dict[str, Any]] = None) -> str:
        """Resolve the tenant domain from the configured resolver or static value.

        Args:
            store_options: Optional context passed to the domain resolver.

        Returns:
            The resolved domain string.

        Raises:
            DomainResolverError: The resolver function raised or returned an
                invalid value.
        """
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
        """Normalize a domain-like value for comparison.

        Args:
            value: A domain or URL string, or None.

        Returns:
            The value lowercased, scheme-qualified, and without a trailing
            slash. Falsy input is returned unchanged.
        """
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
        """Parse an error response body as JSON.

        Args:
            response: The HTTP response to parse.

        Returns:
            The parsed JSON body, or a fallback dict with 'error_description'
            when the body is not valid JSON.
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

    def _map_anonymous_error(
        self,
        status_code: int,
        error_data: dict[str, Any],
        operation: str,
    ) -> Exception:
        """Map a server error response to a typed exception.

        Args:
            status_code: The HTTP status code of the response.
            error_data: The parsed error response body.
            operation: One of 'create', 'token', 'logout', 'introspect'.

        Returns:
            The exception instance. Does not raise it.
        """
        code = error_data.get("error", "")
        description = error_data.get("error_description") or f"Anonymous {operation} failed"

        if code in ("session_expired", "invalid_session_token"):
            return _AnonymousSessionExpired(description)
        if status_code == 400 and "Proof-of-Possession" in description:
            return AnonymousSessionClientNotSupportedError(description, error_data)
        if code == "feature_not_enabled":
            return AnonymousSessionFeatureNotEnabledError(description, error_data)
        if code == "unauthorized_client":
            return AnonymousSessionClientNotEnabledError(description, error_data)
        if code in ("invalid_target", "invalid_request"):
            return AnonymousSessionResourceServerError(description, error_data)
        if code == "invalid_scope":
            return AnonymousSessionScopeError(description, error_data)

        if operation == "create":
            return AnonymousSessionCreateError(description, cause=error_data)
        if operation == "token":
            return AnonymousSessionTokenError(description, error_data)
        if operation == "logout":
            return AnonymousSessionLogoutError(description, error_data)
        if operation == "introspect":
            return AnonymousSessionIntrospectError(description, error_data)
        return AnonymousSessionApiError(code or "anonymous_error", description, error_data)

    # ============================================================================
    # METADATA VALIDATION
    # ============================================================================

    @staticmethod
    def _validate_metadata(metadata: Optional[dict[str, Any]]) -> None:
        """Validate metadata locally before it reaches the network.

        Args:
            metadata: The metadata dict to validate, or None.

        Raises:
            AnonymousSessionCreateError: metadata is not a dict, contains a
                disallowed key, a non-string value, or exceeds 1KB.
        """
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
        """Encrypt an anonymous session context for storage.

        Args:
            context: The context to encrypt.

        Returns:
            The encrypted context string.
        """
        return encrypt(context.model_dump(), self._secret, ANON_TOKEN_SALT)

    def _decrypt_context(self, stored: Any) -> AnonymousSessionContext:
        """Decrypt and validate a stored anonymous session record.

        Args:
            stored: The raw record read from the anonymous store.

        Returns:
            The decrypted AnonymousSessionContext.

        Raises:
            _AnonymousSessionExpired: The record is missing, malformed, or
                fails to decrypt or validate.
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
    # SESSION CREATION
    # ============================================================================

    async def _create_session_at(
        self,
        domain: str,
        *,
        audience: Optional[str],
        scope: Optional[str],
        metadata: Optional[dict[str, Any]],
        store_options: Optional[dict[str, Any]],
    ) -> AnonymousSession:
        """Create a fresh anonymous session against a resolved domain.

        Args:
            domain: The resolved tenant domain.
            audience: Audience for the new session, or None.
            scope: Scope for the new session, or None.
            metadata: Metadata to attach at creation, or None.
            store_options: Options passed to the anonymous store.

        Returns:
            The newly created AnonymousSession, with is_new=True.

        Raises:
            AnonymousSessionCreateError: The request failed, or the response
                was invalid or missing required fields.
        """
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
                raise AnonymousSessionCreateError("Failed to reach the anonymous token endpoint") from e

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
                raise AnonymousSessionCreateError("Failed to parse anonymous token response") from e

        if not token_response.session_token:
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

    async def _remint(
        self, context: AnonymousSessionContext, store_options: Optional[dict[str, Any]]
    ) -> AnonymousSession:
        """Re-mint an access token using the stored session token.

        Args:
            context: The current decrypted session context.
            store_options: Options passed to the anonymous store.

        Returns:
            The refreshed AnonymousSession. is_new is True only when the
            retry-once fallback created a brand-new session.

        Raises:
            AnonymousSessionTokenError: The request failed, or the response was
                invalid.
        """
        domain = context.domain or await self._resolve_domain(store_options)
        base_url = f"https://{domain}"
        body: dict[str, Any] = {
            "client_id": self._client_id,
            "session_token": context.session_token,
        }
        if self._client_secret:
            body["client_secret"] = self._client_secret

        async with self._get_http_client() as client:
            try:
                response = await client.post(f"{base_url}/anonymous/token", json=body)
            except httpx.HTTPError as e:
                raise AnonymousSessionTokenError("Failed to reach the anonymous token endpoint") from e

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
                raise AnonymousSessionTokenError("Failed to parse anonymous token response") from e

        now = int(time.time())
        new_context = AnonymousSessionContext(
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
    # LOGIN INJECTION SUPPORT
    # ============================================================================

    async def get_session_token_for_injection(
        self, store_options: Optional[dict[str, Any]] = None
    ) -> Optional[str]:
        """Read the active session token for login injection without renewing.

        Args:
            store_options: Options passed to the anonymous store.

        Returns:
            The raw session token, or None when there is no store, no active
            session, or the stored record cannot be decrypted.
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
    # PUBLIC API
    # ============================================================================

    async def create_session(
        self,
        options: Optional[Union[CreateAnonymousSessionOptions, dict[str, Any]]] = None,
        *,
        audience: Optional[str] = None,
        scope: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
        store_options: Optional[dict[str, Any]] = None,
    ) -> AnonymousSession:
        """Mint a fresh anon@<uuid> identity.

        Args:
            options: Optional bundle of audience/scope/metadata, accepted as a
                CreateAnonymousSessionOptions or a plain dict. Explicit keyword
                arguments below always win over the same field on options.
            audience: Audience for the session. Falls back to options.audience,
                then to the client's configured default, when omitted.
            scope: Scope for the session. Falls back to options.scope, then to
                the client's configured default, when omitted.
            metadata: Metadata to attach at creation, up to 1KB. Cannot be
                changed after creation. Falls back to options.metadata.
            store_options: Options passed to the anonymous store.

        Returns:
            The newly created AnonymousSession.

        Raises:
            ConfigurationError: No anonymous_store configured.
            AnonymousSessionCreateError: Invalid options, local validation
                failure, or server rejection.
        """
        self._require_store()
        if options is not None:
            if isinstance(options, dict):
                try:
                    options = CreateAnonymousSessionOptions(**options)
                except ValidationError as e:
                    raise AnonymousSessionCreateError(
                        "Invalid create_session options", code="invalid_options"
                    ) from e
            audience = audience if audience is not None else options.audience
            scope = scope if scope is not None else options.scope
            metadata = metadata if metadata is not None else options.metadata
        self._validate_metadata(metadata)
        audience = audience or self._default_audience
        scope = scope or self._default_scope
        domain = await self._resolve_domain(store_options)
        return await self._create_session_at(
            domain, audience=audience, scope=scope, metadata=metadata, store_options=store_options
        )

    async def get_token(self, store_options: Optional[dict[str, Any]] = None) -> AnonymousSession:
        """Return a valid anonymous access token, renewing or re-minting as needed.

        Args:
            store_options: Options passed to the anonymous store.

        Returns:
            The current or refreshed AnonymousSession.

        Raises:
            ConfigurationError: No anonymous_store configured.
            AnonymousSessionTokenError: No active session, or an unrecoverable
                failure.
        """
        self._require_store()
        stored = await self._anonymous_store.get(ANON_IDENTIFIER, options=store_options)
        if not stored:
            raise AnonymousSessionTokenError("No active anonymous session. Call create_session() first.")

        try:
            context = self._decrypt_context(stored)
        except _AnonymousSessionExpired:
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
                # Cross-tenant reuse must be structurally impossible, so
                # discard and mint fresh under the current tenant instead.
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

    async def introspect(
        self, store_options: Optional[dict[str, Any]] = None
    ) -> AnonymousSessionIntrospection:
        """Return the current anonymous session status without mutating the store.

        Args:
            store_options: Options passed to the anonymous store.

        Returns:
            The current AnonymousSessionIntrospection.

        Raises:
            ConfigurationError: No anonymous_store configured.
            AnonymousSessionIntrospectError: No active session, or a request
                failure.
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

    async def logout(self, store_options: Optional[dict[str, Any]] = None) -> None:
        """Clear the locally-held anonymous session without revoking issued tokens.

        Local state is cleared unconditionally, even when the remote call
        fails, since there is no server-side session to keep in sync with.

        Args:
            store_options: Options passed to the anonymous store.

        Raises:
            ConfigurationError: No anonymous_store configured.
            AnonymousSessionLogoutError: The remote logout call failed for a
                reason other than the session already being expired/invalid.
        """
        self._require_store()
        stored = await self._anonymous_store.get(ANON_IDENTIFIER, options=store_options)
        if not stored:
            return

        try:
            context = self._decrypt_context(stored)
        except _AnonymousSessionExpired:
            context = None

        error_to_raise: Optional[Exception] = None
        error_cause: Optional[BaseException] = None

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
                    response = await client.post(f"{base_url}/anonymous/logout", json=body)
            except httpx.HTTPError as e:
                error_to_raise = AnonymousSessionLogoutError(
                    "Failed to reach the anonymous logout endpoint"
                )
                error_cause = e
            else:
                if response.status_code != 200:
                    error_data = self._parse_anonymous_error_body(response)
                    mapped = self._map_anonymous_error(response.status_code, error_data, "logout")
                    if not isinstance(mapped, _AnonymousSessionExpired):
                        error_to_raise = mapped

        await self._anonymous_store.delete(ANON_IDENTIFIER, options=store_options)

        if error_to_raise is not None:
            raise error_to_raise from error_cause
