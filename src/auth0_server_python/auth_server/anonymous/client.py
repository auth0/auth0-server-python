"""
Anonymous Sessions client for auth0-server-python SDK.
Handles pre-login anon@ identity operations against the Auth0 anonymous session API.
"""

import json
import time
from typing import Any, Callable, Optional, Union

import httpx
from pydantic import ValidationError

from auth0_server_python.auth_schemes.client_assertion import (
    CLIENT_ASSERTION_TYPE,
    build_client_assertion,
    validate_client_assertion_key,
)
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
from auth0_server_python.error import (
    AnonymousSessionCreateError,
    AnonymousSessionTokenError,
    ConfigurationError,
    DomainResolverError,
    _AnonymousSessionExpired,
)
from auth0_server_python.utils.helpers import (
    State,
    build_domain_resolver_context,
    validate_resolved_domain_value,
)

from .helpers import (
    ANON_IDENTIFIER,
    TRANSFER_AUDIENCE,
    decode_anonymous_sub,
    find_token_set,
    map_anonymous_error,
    normalize_url,
    parse_anonymous_error_body,
    upsert_token_set,
    validate_metadata,
)


class AnonymousClient:
    """Client for Auth0 anonymous session operations."""

    def __init__(
        self,
        domain: Union[str, Callable, None],
        client_id: str,
        client_secret: Optional[str],
        anonymous_store=None,
        default_audience: Optional[str] = None,
        default_scope: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
        client_assertion_signing_key: Optional[str] = None,
        client_assertion_signing_alg: Optional[str] = None,
    ):
        if callable(domain):
            self._domain = None
            self._domain_resolver = domain
        else:
            self._domain = domain
            self._domain_resolver = None
        self._client_id = client_id
        self._client_secret = client_secret
        self._client_assertion_signing_key = client_assertion_signing_key
        self._client_assertion_signing_alg = client_assertion_signing_alg or "RS256"
        if client_assertion_signing_key:
            validate_client_assertion_key(
                client_assertion_signing_key, self._client_assertion_signing_alg
            )
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
        kwargs.setdefault("timeout", 5.0)
        return httpx.AsyncClient(headers=headers, **kwargs)

    def _require_store(self) -> None:
        """Raise ConfigurationError when no anonymous_store is configured.

        Raises:
            ConfigurationError: No anonymous_store configured.
        """
        if self._anonymous_store is None:
            raise ConfigurationError(
                "AnonymousClient requires its own anonymous_store, distinct from "
                "ServerClient's state_store. Writing anonymous state into the same "
                "store instance can silently overwrite the authenticated session."
            )

    def _apply_client_auth(self, body: dict[str, Any], domain: str) -> None:
        """Inject client credentials into a JSON request body.

        Args:
            body: The outgoing request body dict, mutated in place.
            domain: The target tenant domain, used as the assertion audience.
        """
        if self._client_assertion_signing_key:
            body["client_assertion"] = build_client_assertion(
                self._client_assertion_signing_key,
                self._client_id,
                f"https://{domain}/",
                self._client_assertion_signing_alg,
            )
            body["client_assertion_type"] = CLIENT_ASSERTION_TYPE
        elif self._client_secret:
            body["client_secret"] = self._client_secret

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
        self._apply_client_auth(payload, domain)
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
                error_data = parse_anonymous_error_body(response)
                mapped = map_anonymous_error(error_data, "create")
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
        sub = decode_anonymous_sub(token_response.access_token)
        token_set = AnonymousTokenSetEntry(
            access_token=token_response.access_token,
            expires_at=now + token_response.expires_in,
            audience=audience,
            scope=scope,
            granted_scope=token_response.scope,
        )
        context = AnonymousSessionContext(
            session_token=token_response.session_token,
            token_sets=[token_set],
            session_expires_at=now + token_response.session_expires_in if token_response.session_expires_in is not None else None,
            metadata=metadata,
            created_at=now,
            domain=domain,
            sub=sub,
        )
        await self._anonymous_store.set(
            ANON_IDENTIFIER,
            context.model_dump(),
            options=store_options,
        )
        return AnonymousSession(
            access_token=token_set.access_token,
            expires_at=token_set.expires_at,
            session_expires_at=context.session_expires_at,
            metadata=context.metadata,
            sub=context.sub,
            scope=token_set.granted_scope,
        )

    async def _remint(
        self,
        context: AnonymousSessionContext,
        audience: Optional[str],
        scope: Optional[str],
        store_options: Optional[dict[str, Any]],
    ) -> AnonymousSession:
        """Re-mint an access token using the stored session token.

        Args:
            context: The current session context.
            audience: Audience to request for the new token.
            scope: Scope to request for the new token.
            store_options: Options passed to the anonymous store.

        Returns:
            The refreshed AnonymousSession.

        Raises:
            AnonymousSessionTokenError: The request failed, or the response was
                invalid.
            AnonymousSessionCreateError: The session expired and the silent
                re-creation failed.
        """
        domain = context.domain or await self._resolve_domain(store_options)
        body: dict[str, Any] = {
            "client_id": self._client_id,
            "session_token": context.session_token,
        }
        self._apply_client_auth(body, domain)
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
                error_data = parse_anonymous_error_body(response)
                mapped = map_anonymous_error(error_data, "token")
                if isinstance(mapped, _AnonymousSessionExpired):
                    # One follow-up create call on expiry, never a loop.
                    return await self._create_session_at(
                        domain,
                        audience=audience,
                        scope=scope,
                        metadata=context.metadata,
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
        new_sub = decode_anonymous_sub(token_response.access_token)
        token_set = AnonymousTokenSetEntry(
            access_token=token_response.access_token,
            expires_at=now + token_response.expires_in,
            audience=audience,
            scope=scope,
            granted_scope=token_response.scope,
        )
        result = AnonymousSession(
            access_token=token_set.access_token,
            expires_at=token_set.expires_at,
            session_expires_at=now + token_response.session_expires_in if token_response.session_expires_in is not None else context.session_expires_at,
            metadata=context.metadata,
            sub=new_sub if new_sub is not None else context.sub,
            scope=token_response.scope,
        )

        # Re-read to preserve a concurrent remint and skip a stale write.
        current_stored = await self._anonymous_store.get(ANON_IDENTIFIER, options=store_options)
        if not current_stored:
            return result
        try:
            current_context = AnonymousSessionContext.model_validate(current_stored)
        except Exception:
            return result
        if current_context.session_token != context.session_token:
            return result

        # Only backfill sub when the stored context has none.
        sub_update = {"sub": new_sub} if new_sub is not None and current_context.sub is None else {}
        updated_context = upsert_token_set(
            current_context.model_copy(update={
                "session_token": new_session_token,
                "session_expires_at": now + token_response.session_expires_in if token_response.session_expires_in is not None else context.session_expires_at,
                **sub_update,
            }),
            token_set,
        )
        await self._anonymous_store.set(
            ANON_IDENTIFIER,
            updated_context.model_dump(),
            options=store_options,
        )
        return result

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
            context = AnonymousSessionContext.model_validate(stored)
        except Exception:
            return None
        # Prevents a tenant-A session token from minting a transfer ticket usable at tenant-B's login.
        # In resolver mode, an unknown stored domain (legacy session) is treated as a mismatch.
        domain_unknown = not context.domain and self._domain_resolver is not None
        domain_mismatch = context.domain and normalize_url(context.domain) != normalize_url(
            origin_domain
        )
        if domain_unknown or domain_mismatch:
            return None
        return await self._mint_transfer_token(context.session_token, origin_domain)

    async def _mint_transfer_token(
        self, session_token: str, origin_domain: str
    ) -> Optional[str]:
        """Exchange a session token for a transfer ticket.

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
        self._apply_client_auth(body, origin_domain)

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
        validate_metadata(metadata)
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
            AnonymousSessionCreateError: The session expired and the silent
                re-creation failed.
        """
        self._require_store()
        stored = await self._anonymous_store.get(ANON_IDENTIFIER, options=store_options)
        if not stored:
            raise AnonymousSessionTokenError("No active anonymous session. Call create_session() first.")

        eff_audience = audience or self._default_audience
        eff_scope = scope or self._default_scope

        try:
            context = AnonymousSessionContext.model_validate(stored)
        except Exception as e:
            await self._anonymous_store.delete(ANON_IDENTIFIER, options=store_options)
            raise AnonymousSessionTokenError(
                "The stored anonymous session is corrupt or unreadable. "
                "Call create_session() to start a new session.",
                code="invalid_session_state",
            ) from e

        current_domain = await self._resolve_domain(store_options)
        # In resolver mode, an unknown stored domain (legacy session) is treated as a mismatch.
        domain_unknown = not context.domain and self._domain_resolver is not None
        domain_mismatch = context.domain and normalize_url(context.domain) != normalize_url(
            current_domain
        )
        if domain_unknown or domain_mismatch:
            return await self._create_session_at(
                current_domain,
                audience=eff_audience,
                scope=eff_scope,
                metadata=None,
                store_options=store_options,
            )

        now = int(time.time())
        token_set = find_token_set(context.token_sets, eff_audience, eff_scope)
        if token_set and token_set.expires_at - State.SESSION_EXPIRY_LEEWAY_SECONDS > now:
            return AnonymousSession(
                access_token=token_set.access_token,
                expires_at=token_set.expires_at,
                session_expires_at=context.session_expires_at,
                metadata=context.metadata,
                sub=context.sub,
                scope=token_set.granted_scope,
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
            context = AnonymousSessionContext.model_validate(stored)
        except Exception:
            return None
        if context.domain:
            try:
                current_domain = await self._resolve_domain(store_options)
            except Exception:
                return None
            if normalize_url(context.domain) != normalize_url(current_domain):
                return None
        return AnonymousSessionData(
            sub=context.sub,
            metadata=context.metadata,
            created_at=context.created_at,
            session_expires_at=context.session_expires_at,
            domain=context.domain,
        )
