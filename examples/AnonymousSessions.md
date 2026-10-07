# Anonymous Sessions

Anonymous Sessions give a visitor an Auth0 identity **before they log in**. Each visitor gets a persistent `anon@<uuid>` subject plus an access token, with up to 1 KB of key/value metadata attached at creation. At login, the SDK carries the session to Auth0 as a short-lived transfer ticket so Post-Login / Pre-User-Registration Actions can read the anonymous data via `event.anonymous_session`. Nothing migrates onto the real user profile automatically. The Action author decides what to persist.

## Table of Contents

- [Anonymous Sessions](#anonymous-sessions)
  - [Table of Contents](#table-of-contents)
  - [Setup](#setup)
  - [Creating a Session](#creating-a-session)
  - [Getting a Token (Renewal Ladder)](#getting-a-token-renewal-ladder)
  - [Reading the Session](#reading-the-session)
  - [Logging Out](#logging-out)
  - [Login Injection](#login-injection)
  - [Rate-Limiting `get_token()`](#rate-limiting-get_token)
  - [Error Handling](#error-handling)
  - [Additional Resources](#additional-resources)

## Setup

Before using the anonymous sessions API, the `anonymous_sessions_enabled` flag must be turned on for your tenant, and the application/client must be enabled for the feature.

Pass an `anonymous_store` to `ServerClient`, alongside your existing `state_store` and `transaction_store`:

```python
server_client = ServerClient(
    domain="your-tenant.auth0.com",
    client_id="...",
    client_secret="...",
    secret="...",
    state_store=my_state_store,
    transaction_store=my_transaction_store,
    anonymous_store=my_anonymous_store,   # its own store instance, not state_store
)
```

Give `anonymous_store` its own store instance, not `state_store` with a different identifier. If you omit it, `create_session()`, `get_token()`, and `logout()` raise `ConfigurationError` before any write. `get_session()` returns `None`.

The anonymous store implements the same `StateStore` ABC as your existing session store. A minimal cookie-backed example:

```python
from auth0_server_python.store import StateStore

class AnonymousSessionStore(StateStore):
    def __init__(self, secret: str):
        super().__init__({"secret": secret})

    async def set(self, identifier, state, remove_if_expires=False, options=None):
        # Encrypt and write to a cookie or server-side store.
        # The SDK passes a plain dict; encryption is your responsibility.
        encrypted = self.encrypt(identifier, state)
        options["response"].set_cookie("_a0_anon", encrypted, httponly=True, samesite="lax")

    async def get(self, identifier, options=None):
        value = options["request"].cookies.get("_a0_anon")
        if not value:
            return None
        return self.decrypt(identifier, value)

    async def delete(self, identifier, options=None):
        options["response"].delete_cookie("_a0_anon")
```

`self.encrypt` / `self.decrypt` are helpers from the `StateStore` base class that derive a key from your `secret` and the store identifier. The cookie name `_a0_anon` must be distinct from the cookie name used by your `state_store` - a shared name will silently overwrite the authenticated session. See `examples/ConfigureStore.md` for the full store configuration reference.

> [!IMPORTANT]
> **Encryption is your responsibility.** The SDK writes the anonymous session as a plain dict with no encryption applied. If your `anonymous_store` is cookie-backed or otherwise persists data outside a trusted server boundary, you must encrypt the payload before writing and decrypt it on read. This is the same responsibility you already have for `state_store`.

## Creating a Session

```python
session = await server_client.anonymous.create_session(
    audience="https://api.example.com",
    scope="read:cart write:cart",
    metadata={"cart_id": "cart_456"},
    store_options=store_options,
)
```

`metadata` is **set once, at creation, and never updated**. Any JSON-serializable value is accepted, ≤1 KB total (UTF-8 JSON byte length). Oversized or non-JSON-serializable metadata is rejected client-side before any network call.

`AnonymousSession` returns `access_token`, `expires_at`, `session_expires_at`, `metadata`, `sub`, and `scope`.

## Getting a Token

```python
token = await server_client.anonymous.get_token(store_options=store_options)
```

Renewal logic, in order:

1. Cached access token still fresh, returned with no network call.
2. Expired, re-minted using the stored session token (not a refresh-token grant, since anonymous sessions never issue refresh tokens).
3. Session token expired, raises `AnonymousSessionTokenError` with code `session_expired` and clears the stored session. Token structurally invalid raises with code `invalid_session_token` and also clears. Call `create_session()` to start a new session in either case.
4. Any other error, raised as a typed exception. No swallow, no auto-retry.

> [!IMPORTANT]
> **On `session_expired` or `invalid_session_token`, the previous anonymous identity is gone.** The SDK clears the stored session before raising, so a subsequent `get_session()` returns `None`. Neither error surfaces the previous identity (its `sub` or `metadata`). Call `create_session()` to start fresh.
>
> Do any identity-dependent work, such as cart or data migration, at **login time**, not on expiry. Read `get_session().sub` before calling `complete_interactive_login()`. That is the normal migration path and is unaffected by the expiry clear. A session expiring before the visitor ever logs in is rare given the session lifetime, and the correct response is simply to create a new one.

## Reading the Session

```python
data = await server_client.anonymous.get_session(store_options=store_options)
```

Returns the stored anonymous identity without calling Auth0, or `None` when there is no session, the stored record is unreadable, or the stored domain does not match the current tenant. Use it to check whether a visitor already has an anonymous identity before deciding to call `create_session()`.

`AnonymousSessionData` carries `sub`, `metadata`, `created_at`, `session_expires_at`, and `domain` - the identity fields only. It never exposes the session token or an access token. To obtain a usable access token, call `get_token()`.

Unlike the other `.anonymous.*` methods, `get_session()` returns `None` rather than raising when no `anonymous_store` is configured.

## Logging Out

```python
await server_client.anonymous.logout(store_options=store_options)
```

> [!CAUTION]
> **`logout()` does not revoke.** There is no server-side anonymous session store to revoke against, this clears only the locally-held session context. Any access token already issued for this anonymous session remains valid until its natural expiry.

Authenticated (OIDC) logout also ends an active anonymous session. When you call `ServerClient.logout()` and an anonymous store is configured, the SDK clears the locally-held anonymous session before returning the logout URL. This is a local clear only, with no remote call (consistent with `anonymous.logout()`, which also does not revoke server-side). It prevents the next visitor on a shared device from having the previous visitor's anonymous identity re-linked at their login. If no anonymous session is active, nothing is cleared.

## Login Injection

When an anonymous session is active, `start_interactive_login()` automatically injects an `anon_transfer_token` transfer ticket into the `/authorize` URL, no code change needed at your call site. If no anonymous session exists, behavior is unchanged.

The raw `session_token` never goes on the URL. At the moment the `/authorize` URL is built, the SDK exchanges the stored session token for a short-lived (30s) single-use ticket (`anon_transfer_token`) via `POST /anonymous/token`, and forwards only that ticket as the `anon_transfer_token` query parameter. The raw session token stays inside the SDK's store and the ticket is never persisted. The ticket is short-lived and grants no authorization on its own, but you should still set `Referrer-Policy: no-referrer` on your login pages and never log the authorize URL.

If the exchange errors (network failure, a non-200, or an unparseable response), login proceeds with no ticket and no linking, and never aborts the login.

After `complete_interactive_login` succeeds, the SDK clears the anonymous session by default. To keep it active across the login boundary:

```python
server_client = ServerClient(
    ...
    clear_anonymous_session_on_login=False,
)
```

## Rate-Limiting `get_token()`

`get_token()` makes at most one upstream Auth0 call per invocation. It does not protect against an attacker calling your route repeatedly. `POST /anonymous/token` is an unauthenticated, token-issuing endpoint. **You must rate-limit any route in your application that calls `get_token()` on an anonymous session**, the same way you would rate-limit any other unauthenticated token-issuing path. The SDK has no request-level context to do this itself.

## Error Handling

All anonymous session errors subclass `AnonymousSessionError`, carrying a `.code` you can branch on:

```python
from auth0_server_python.error import (
    AnonymousSessionCreateError,
    AnonymousSessionTokenError,
)

try:
    session = await server_client.anonymous.create_session(audience="...", scope="...")
except AnonymousSessionCreateError as e:
    if e.code == "feature_not_enabled":
        ...
```

### Error Hierarchy

```
AnonymousSessionError           base class, never raised directly
  AnonymousSessionCreateError   raised by create_session()
  AnonymousSessionTokenError    raised by get_token()
```

### `AnonymousSessionCreateError` codes

| `.code` | When |
|---------|------|
| `"feature_not_enabled"` | anonymous sessions not enabled on this tenant/client (server-returned code, passed through unchanged) |
| `"anonymous_create_error"` | generic platform error on the create path |
| `"missing_session_token"` | platform response omitted the session token (misconfigured tenant) |
| `"invalid_metadata"` | metadata is not a dict or contains non-JSON-serializable values |
| `"metadata_too_large"` | metadata exceeds the 1 KB limit |
| `"invalid_options"` | unrecognised key in `create_session()` options |

The platform may return other codes (e.g. `"insufficient_scope"`) and these are passed through on `.code` unchanged.

### `AnonymousSessionTokenError` codes

| `.code` | When |
|---------|------|
| `"session_expired"` | session token has expired - call `create_session()` to start a new session |
| `"invalid_session_token"` | session token is structurally invalid (e.g. rotated or revoked) - call `create_session()` to recover |
| `"invalid_session_state"` | stored session data is corrupt or unreadable - call `create_session()` to recover |
| `"anonymous_token_error"` | no active session, network error, parse error, or generic platform error on the renewal path |

> **Note on naming.** The SDK spec names this class `AnonymousSessionTokenExpiredError`. This SDK uses `AnonymousSessionTokenError` - a deliberate broadening, since the class covers all `get_token()` failures, not just expiry. The `.code` values are stable and safe to branch on.

### Handling expired and invalid session tokens

Both `session_expired` and `invalid_session_token` mean the stored session is permanently unusable. The SDK clears it before raising, so `get_session()` returns `None` immediately after. The correct response is to start a fresh session:

```python
from auth0_server_python.error import AnonymousSessionTokenError

try:
    token = await server_client.anonymous.get_token(store_options=store_options)
except AnonymousSessionTokenError as e:
    if e.code == "session_expired":
        # The session lifetime elapsed. Start a fresh one.
        session = await server_client.anonymous.create_session(
            audience="https://api.example.com",
            scope="read:cart write:cart",
            store_options=store_options,
        )
        token = await server_client.anonymous.get_token(store_options=store_options)
    elif e.code == "invalid_session_token":
        # The token is structurally invalid (e.g. rotated or revoked).
        session = await server_client.anonymous.create_session(
            audience="https://api.example.com",
            scope="read:cart write:cart",
            store_options=store_options,
        )
        token = await server_client.anonymous.get_token(store_options=store_options)
    else:
        raise
```

If your application treats both cases identically, you can handle them together:

```python
from auth0_server_python.error import AnonymousSessionTokenError

try:
    token = await server_client.anonymous.get_token(store_options=store_options)
except AnonymousSessionTokenError as e:
    if e.code in ("session_expired", "invalid_session_token"):
        session = await server_client.anonymous.create_session(
            audience="https://api.example.com",
            scope="read:cart write:cart",
            store_options=store_options,
        )
        token = await server_client.anonymous.get_token(store_options=store_options)
    else:
        raise
```

The two codes are kept distinct so callers that need to differentiate (for example, to log a metric or alert on unexpected token invalidation) can do so without parsing the message string.
