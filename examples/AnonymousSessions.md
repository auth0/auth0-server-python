# Anonymous Sessions

Anonymous Sessions give a visitor an Auth0 identity **before they log in**. Each visitor gets a persistent `anon@<uuid>` subject plus an access token, with up to 1 KB of key/value metadata (cart, preferences) attached at creation. At login, the session token rides into `/authorize` so Post-Login / Pre-User-Registration Actions can read the anonymous data via `event.anonymous_session` — nothing migrates onto the real user profile automatically; the Action author decides what to persist.

> [!NOTE]
> Anonymous Sessions support for server SDKs is in Early Access, gated by a tenant-level, paid add-on feature flag (`anonymous_sessions_enabled`). `auth0-server-python` mounts no routes and sets no cookies — this guide covers the framework-agnostic core only.

## Table of Contents

- [Anonymous Sessions](#anonymous-sessions)
  - [Table of Contents](#table-of-contents)
  - [Setup](#setup)
  - [Creating a Session](#creating-a-session)
  - [Getting a Token (Renewal Ladder)](#getting-a-token-renewal-ladder)
  - [Introspecting a Session](#introspecting-a-session)
  - [Logging Out](#logging-out)
  - [Login Injection](#login-injection)
  - [Rate-Limiting `get_token()`](#rate-limiting-get_token)
  - [Error Handling](#error-handling)
  - [Known Limitations](#known-limitations)
  - [Additional Resources](#additional-resources)

## Setup

Before using the anonymous sessions API, the `anonymous_sessions_enabled` flag must be turned on for your tenant (contact your Auth0 account team — there is no self-serve path yet), and the application/client must be enabled for the feature.

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

Give `anonymous_store` its own store instance, not `state_store` with a different identifier. If you omit it, every `.anonymous.*` call raises `ConfigurationError` before any write.

## Creating a Session

```python
session = await server_client.anonymous.create_session(
    audience="https://api.example.com",
    scope="read:cart write:cart",
    metadata={"cart_id": "cart_456"},
    store_options=store_options,
)
```

`metadata` is **set once, at creation, and never updated** — there is no platform update endpoint for anonymous sessions. Top-level string values only, ≤1 KB total (UTF-8 JSON byte length); oversized or non-string values are rejected client-side before any network call.

`AnonymousSession` never exposes the raw session token — only `sub`, `session_id`, `access_token`, `expires_at`, `session_expires_at`, `metadata`, and `is_new`.

> [!IMPORTANT]
> **Always check `is_new`.** It is `True` both on the first call to `create_session()` and on a *silent* re-mint (see below) — the only signal your application receives when the anonymous `sub` has changed. Any code correlating data on `sub` (e.g. a cart keyed by anonymous user) must check this on every call.

## Getting a Token

```python
token = await server_client.anonymous.get_token(store_options=store_options)
```

Renewal logic, in order:

1. Cached access token still fresh → returned with no network call.
2. Expired → re-minted using the stored session token (not a refresh-token grant — anonymous sessions never issue refresh tokens).
3. Session token also expired or invalid → a **brand-new session is silently created, once**. Metadata from the old session is permanently lost, and `sub` changes. This never raises — an anonymous pre-login session carries no authorization, so re-minting crosses no trust boundary.
4. Any other error → raised as a typed exception. No swallow, no auto-retry beyond the one re-mint in step 3.

## Introspecting a Session

```python
status = await server_client.anonymous.introspect(store_options=store_options)
```

`introspect()` is read-only: it returns the current session status without renewing the token or changing `sub`.

## Logging Out

```python
await server_client.anonymous.logout(store_options=store_options)
```

> [!CAUTION]
> **`logout()` does not revoke.** There is no server-side anonymous session store to revoke against, this clears only the locally-held encrypted context. Any access token already issued for this anonymous session remains valid until its natural expiry.

## Login Injection

When an anonymous session is active, `start_interactive_login()` automatically includes the session token in the `/authorize` request, no code change needed at your call site. If no anonymous session exists, behavior is same as today.

The token travels as a query parameter to `/authorize`, which means it lands in browser history, `Referer` headers, and access logs. This is because the token grants no authorization on its own and the request is a browser-to-Auth0 HTTPS redirect, but you should still set `Referrer-Policy: no-referrer` on your login pages, and never log the authorize URL.

Pushed Authorization Requests (PAR) are not supported for anonymous sessions — injection is suppressed entirely on that code path.

## Rate-Limiting `get_token()`

`get_token()`'s retry-once bound caps amplification to two upstream Auth0 calls *per invocation*. It does not protect against an attacker calling your route repeatedly. `POST /anonymous/token` is an unauthenticated, token-issuing endpoint. **You must rate-limit any route in your application that calls `get_token()` on an anonymous session**, the same way you would rate-limit any other unauthenticated token-issuing path. The SDK has no request-level context to do this itself.

## Error Handling

All anonymous session errors subclass `AnonymousSessionApiError`, carrying a `.code` you can branch on:

```python
from auth0_server_python.error import (
    AnonymousSessionFeatureNotEnabledError,
    AnonymousSessionClientNotEnabledError,
    AnonymousSessionClientNotSupportedError,
    AnonymousSessionResourceServerError,
    AnonymousSessionScopeError,
    AnonymousSessionCreateError,
    AnonymousSessionTokenError,
    AnonymousSessionIntrospectError,
    AnonymousSessionLogoutError,
)

try:
    session = await server_client.anonymous.create_session(audience="...", scope="...")
except AnonymousSessionFeatureNotEnabledError:
    ...
```

## Known Limitations

- **DPoP is not supported.** `AnonymousClient` has no `dpop_key` parameter anywhere in its public API. A tenant/client configured with `require_proof_of_possession: true` cannot use anonymous sessions, you will see `AnonymousSessionClientNotSupportedError`.
- **PAR, CIBA, Device Flow, RAR, and mTLS clients are not supported** for anonymous sessions.
- **No server-side revocation.** See [Logging Out](#logging-out) above.