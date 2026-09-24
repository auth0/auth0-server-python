"""
Anonymous Sessions client for auth0-server-python SDK.
Handles pre-login anon@ identity operations against the Auth0 anonymous session API.
"""

import base64
import json
import time
from typing import Any, Callable, Optional, Union

import httpx
from pydantic import ValidationError

from auth0_server_python.auth_types import (
    AnonymousCreateTokenResponse,
    AnonymousSession,
    AnonymousSessionContext,
    AnonymousSessionData,
    AnonymousTokenResponse,
    AnonymousTokenSetEntry,
    AnonymousTransferTokenResponse,
    CreateAnonymousSessionOptions,
)
from auth0_server_python.encryption.encrypt import decrypt, encrypt
from auth0_server_python.error import (
    AnonymousSessionApiError,
    AnonymousSessionClientNotEnabledError,
    AnonymousSessionClientNotSupportedError,
    AnonymousSessionCreateError,
    AnonymousSessionFeatureNotEnabledError,
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

# Audience for the /anonymous/token exchange that mints a short-lived transfer
# ticket for login injection.
TRANSFER_AUDIENCE = "urn:auth0:anon_transfer"

_METADATA_MAX_BYTES = 1024
_DANGEROUS_METADATA_KEYS = frozenset({"__proto__", "constructor", "prototype"})


class AnonymousClient:
    """Client for Auth0 anonymous session operations."""

    def __init__(
        self,
        domain: Union[str, Callable, None],
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
    # TOKEN SET CACHE HELPERS
    # ============================================================================

    @staticmethod
    def _decode_sub(access_token: str) -> Optional[str]:
        """Extract the sub claim from a JWT access token without verifying the signature.

        Args:
            access_token: The token to decode.

        Returns:
            The sub claim, or None for opaque tokens, non-JWT strings, or
            tokens with no sub claim.
        """
        try:
            parts = access_token.split(".")
            if len(parts) != 3:
                return None
            padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(padded))
            sub = payload.get("sub")
            return str(sub) if sub else None
        except Exception:
            return None

    @staticmethod
    def _find_token_set(
        token_sets: list,
        audience: Optional[str],
        scope: Optional[str],
    ) -> Optional[AnonymousTokenSetEntry]:
        for ts in token_sets:
            if ts.audience == audience and ts.scope == scope:
                return ts
        return None

    @staticmethod
    def _upsert_token_set(
        context: AnonymousSessionContext,
        entry: AnonymousTokenSetEntry,
    ) -> AnonymousSessionContext:
        new_sets = [
            ts for ts in context.token_sets
            if not (ts.audience == entry.audience and ts.scope == entry.scope)
        ]
        new_sets.append(entry)
        return context.model_copy(update={"token_sets": new_sets})

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
            operation: One of 'create', 'token'.

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
                disallowed key, a non-JSON-serializable value, or exceeds 1KB.
        """
        if metadata is None:
            return
        if not isinstance(metadata, dict):
            raise AnonymousSessionCreateError("metadata must be a JSON object", code="invalid_metadata")
        for key in metadata:
            if key in _DANGEROUS_METADATA_KEYS:
                raise AnonymousSessionCreateError(
                    f"metadata key '{key}' is not allowed", code="invalid_metadata"
                )
        try:
            size = len(json.dumps(metadata).encode("utf-8"))
        except TypeError as e:
            raise AnonymousSessionCreateError(
                "metadata must contain only JSON-serializable values", code="invalid_metadata"
            ) from e
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
            return AnonymousSessionContext.model_validate(payload)
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
            The newly created AnonymousSession.

        Raises:
            AnonymousSessionCreateError: The request failed, or the response
                was invalid or missing required fields.
        """
        base_url = f"https://{domain}"
        payload: dict[str, Any] = {"client_id": self._client_id}
        if self._client_secret:
            payload["client_secret"] = self._client_secret
        if audience:
            payload["audience"] = audience
        if scope:
            payload["scope"] = scope
        if metadata:
            payload["metadata"] = metadata

        async with self._get_http_client() as client:
            try:
                response = await client.post(f"{base_url}/anonymous/token", json=payload)
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
                data = response.json()
            except (json.JSONDecodeError, ValueError) as e:
                raise AnonymousSessionCreateError("Failed to parse anonymous token response") from e

            if not isinstance(data, dict) or not data.get("session_token"):
                raise AnonymousSessionCreateError(
                    "Anonymous token response contained no session_token. Enable session_token in the response for this tenant.",
                    code="missing_session_token",
                )

            try:
                token_response = AnonymousCreateTokenResponse.model_validate(data)
            except (ValueError, ValidationError) as e:
                raise AnonymousSessionCreateError("Failed to parse anonymous token response") from e

        now = int(time.time())
        sub = self._decode_sub(token_response.access_token)
        token_set = AnonymousTokenSetEntry(
            access_token=token_response.access_token,
            expires_at=now + token_response.expires_in,
            audience=audience,
            scope=scope,
        )
        context = AnonymousSessionContext(
            session_token=token_response.session_token,
            token_sets=[token_set],
            session_expires_at=now + token_response.session_expires_in,
            metadata=metadata,
            created_at=now,
            domain=domain,
            sub=sub,
        )
        await self._anonymous_store.set(
            ANON_IDENTIFIER,
            {"context": self._encrypt_context(context)},
            options=store_options,
        )
        return AnonymousSession(
            access_token=token_set.access_token,
            session_token=context.session_token,
            expires_at=token_set.expires_at,
            session_expires_at=context.session_expires_at,
            metadata=context.metadata,
            sub=context.sub,
        )

    # ============================================================================
    # TOKEN RENEWAL LADDER
    # ============================================================================

    async def _remint(
        self,
        context: AnonymousSessionContext,
        audience: Optional[str],
        scope: Optional[str],
        store_options: Optional[dict[str, Any]],
    ) -> AnonymousSession:
        """Re-mint an access token using the stored session token.

        Args:
            context: The current decrypted session context.
            audience: Audience to request for the new token.
            scope: Scope to request for the new token.
            store_options: Options passed to the anonymous store.

        Returns:
            The refreshed AnonymousSession.

        Raises:
            AnonymousSessionTokenError: The request failed, or the response was
                invalid.
        """
        domain = context.domain or await self._resolve_domain(store_options)
        body: dict[str, Any] = {
            "client_id": self._client_id,
            "session_token": context.session_token,
        }
        if self._client_secret:
            body["client_secret"] = self._client_secret
        if audience:
            body["audience"] = audience
        if scope:
            body["scope"] = scope

        async with self._get_http_client() as client:
            try:
                response = await client.post(f"https://{domain}/anonymous/token", json=body)
            except httpx.HTTPError as e:
                raise AnonymousSessionTokenError("Failed to reach the anonymous token endpoint") from e

            if response.status_code != 200:
                error_data = self._parse_anonymous_error_body(response)
                mapped = self._map_anonymous_error(response.status_code, error_data, "token")
                if isinstance(mapped, _AnonymousSessionExpired):
                    # One follow-up create call on expiry, never a loop.
                    return await self._create_session_at(
                        domain,
                        audience=audience,
                        scope=scope,
                        metadata=None,
                        store_options=store_options,
                    )
                raise mapped

            try:
                token_response = AnonymousTokenResponse.model_validate(response.json())
            except (json.JSONDecodeError, ValueError, ValidationError) as e:
                raise AnonymousSessionTokenError("Failed to parse anonymous token response") from e

        now = int(time.time())
        new_session_token = (
            token_response.session_token
            if token_response.session_token is not None
            else context.session_token
        )
        new_sub = self._decode_sub(token_response.access_token)
        token_set = AnonymousTokenSetEntry(
            access_token=token_response.access_token,
            expires_at=now + token_response.expires_in,
            audience=audience,
            scope=scope,
        )
        result = AnonymousSession(
            access_token=token_set.access_token,
            session_token=new_session_token,
            expires_at=token_set.expires_at,
            session_expires_at=now + token_response.session_expires_in,
            metadata=context.metadata,
            sub=new_sub if new_sub is not None else context.sub,
        )

        # Re-read before writing back so concurrent remints for other audiences
        # are preserved, and writes to a deleted or replaced session are skipped.
        current_stored = await self._anonymous_store.get(ANON_IDENTIFIER, options=store_options)
        if not current_stored:
            return result
        try:
            current_context = self._decrypt_context(current_stored)
        except _AnonymousSessionExpired:
            current_context = context
        if current_context.session_token != context.session_token:
            return result

        # Only update sub when it was not previously stored (token was initially JWE).
        sub_update = {"sub": new_sub} if new_sub is not None and current_context.sub is None else {}
        updated_context = self._upsert_token_set(
            current_context.model_copy(update={
                "session_token": new_session_token,
                "session_expires_at": now + token_response.session_expires_in,
                **sub_update,
            }),
            token_set,
        )
        await self._anonymous_store.set(
            ANON_IDENTIFIER,
            {"context": self._encrypt_context(updated_context)},
            options=store_options,
        )
        return result

    # ============================================================================
    # LOGIN INJECTION SUPPORT
    # ============================================================================

    async def exchange_transfer_token_for_injection(
        self, origin_domain: str, store_options: Optional[dict[str, Any]] = None
    ) -> Optional[str]:
        """Mint a short-lived transfer ticket from the active session for login injection.

        Args:
            origin_domain: The domain the /authorize URL is being built for.
            store_options: Options passed to the anonymous store.

        Returns:
            The minted transfer ticket, or None.
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
        # Prevents a tenant-A session token from minting a transfer ticket usable at tenant-B's login.
        if context.domain and self._normalize_url(context.domain) != self._normalize_url(
            origin_domain
        ):
            return None
        return await self._mint_transfer_token(context.session_token, origin_domain)

    async def _mint_transfer_token(
        self, session_token: str, origin_domain: str
    ) -> Optional[str]:
        """Exchange a session token for a transfer ticket. Fails open.

        Args:
            session_token: The stored anonymous session token.
            origin_domain: The domain the /authorize URL is being built for.

        Returns:
            The minted transfer ticket, or None.
        """
        base_url = f"https://{origin_domain}"
        body: dict[str, Any] = {
            "client_id": self._client_id,
            "session_token": session_token,
            "audience": TRANSFER_AUDIENCE,
        }
        if self._client_secret:
            body["client_secret"] = self._client_secret

        try:
            async with self._get_http_client() as client:
                response = await client.post(f"{base_url}/anonymous/token", json=body)
        except httpx.HTTPError:
            return None
        if response.status_code != 200:
            return None
        try:
            token_response = AnonymousTransferTokenResponse.model_validate(response.json())
        except (json.JSONDecodeError, ValueError, ValidationError):
            return None
        return token_response.anon_transfer_token

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
                    options = CreateAnonymousSessionOptions.model_validate(options)
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

    async def get_token(
        self,
        store_options: Optional[dict[str, Any]] = None,
        *,
        audience: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> AnonymousSession:
        """Return a valid anonymous access token, renewing or re-minting as needed.

        Args:
            store_options: Options passed to the anonymous store.
            audience: Audience to retrieve a token for. Falls back to the
                client's configured default when omitted.
            scope: Scope to retrieve a token for. Falls back to the client's
                configured default when omitted.

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

        eff_audience = audience or self._default_audience
        eff_scope = scope or self._default_scope

        try:
            context = self._decrypt_context(stored)
        except _AnonymousSessionExpired:
            domain = await self._resolve_domain(store_options)
            return await self._create_session_at(
                domain,
                audience=eff_audience,
                scope=eff_scope,
                metadata=None,
                store_options=store_options,
            )

        current_domain = await self._resolve_domain(store_options)
        if context.domain and self._normalize_url(context.domain) != self._normalize_url(
            current_domain
        ):
            return await self._create_session_at(
                current_domain,
                audience=eff_audience,
                scope=eff_scope,
                metadata=context.metadata,
                store_options=store_options,
            )

        now = int(time.time())
        token_set = self._find_token_set(context.token_sets, eff_audience, eff_scope)
        if token_set and token_set.expires_at > now:
            return AnonymousSession(
                access_token=token_set.access_token,
                session_token=context.session_token,
                expires_at=token_set.expires_at,
                session_expires_at=context.session_expires_at,
                metadata=context.metadata,
                sub=context.sub,
            )

        return await self._remint(context, eff_audience, eff_scope, store_options)

    async def logout(self, store_options: Optional[dict[str, Any]] = None) -> None:
        """Clear the locally-held anonymous session without revoking issued tokens.

        Args:
            store_options: Options passed to the anonymous store.

        Raises:
            ConfigurationError: No anonymous_store configured.
        """
        self._require_store()
        stored = await self._anonymous_store.get(ANON_IDENTIFIER, options=store_options)
        if not stored:
            return
        await self._anonymous_store.delete(ANON_IDENTIFIER, options=store_options)

    async def get_session(
        self, store_options: Optional[dict[str, Any]] = None
    ) -> Optional[AnonymousSessionData]:
        """Return stored anonymous session identity without calling Auth0.

        Args:
            store_options: Options passed to the anonymous store.

        Returns:
            The stored AnonymousSessionData, or None when there is no session,
            the session is corrupt, or (in resolver mode) the stored domain
            does not match the current tenant.
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
        if context.domain:
            try:
                current_domain = await self._resolve_domain(store_options)
            except Exception:
                return None
            if self._normalize_url(context.domain) != self._normalize_url(current_domain):
                return None
        return AnonymousSessionData(
            sub=context.sub,
            metadata=context.metadata,
            created_at=context.created_at,
            session_expires_at=context.session_expires_at,
            domain=context.domain,
        )

    async def _end_session_if_active(
        self, store_options: Optional[dict[str, Any]] = None
    ) -> None:
        """Clear the local anonymous session on authenticated logout, if one is active.

        Args:
            store_options: Options passed to the anonymous store.
        """
        if self._anonymous_store is None:
            return
        try:
            stored = await self._anonymous_store.get(ANON_IDENTIFIER, options=store_options)
        except Exception:
            return
        if not stored:
            return
        try:
            await self._anonymous_store.delete(ANON_IDENTIFIER, options=store_options)
        except Exception:
            return
