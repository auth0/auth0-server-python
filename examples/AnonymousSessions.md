# Anonymous Sessions

Anonymous Sessions give a visitor an Auth0 identity **before they log in**. Each visitor gets a persistent `anon@<uuid>` subject plus an access token, with up to 1 KB of key/value metadata attached at creation. At login, the SDK carries the session to Auth0 as a short-lived transfer ticket so Post-Login / Pre-User-Registration Actions can read the anonymous data via `event.anonymous_session`. Nothing migrates onto the real user profile automatically. The Action author decides what to persist.

## Table of Contents

- [Anonymous Sessions](#anonymous-sessions)
  - [Table of Contents](#table-of-contents)
  - [Setup](#setup)
  - [Creating a Session](#creating-a-session)
  - [Getting a Token (Renewal Ladder)](#getting-a-token-renewal-ladder)
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

`metadata` is **set once, at creation, and never updated**. Any JSON-serializable value is accepted, ≤1 KB total (UTF-8 JSON byte length). Oversized, non-JSON-serializable, or dangerous-key (`__proto__`, `constructor`, `prototype`) metadata is rejected client-side before any network call.

`AnonymousSession` returns `session_token`, `access_token`, `expires_at`, `session_expires_at`, and `metadata`.

## Getting a Token

```python
token = await server_client.anonymous.get_token(store_options=store_options)
```

Renewal logic, in order:

1. Cached access token still fresh, returned with no network call.
2. Expired, re-minted using the stored session token (not a refresh-token grant, since anonymous sessions never issue refresh tokens).
3. Session token also expired or invalid, a **brand-new session is silently created, once**. Metadata from the old session is permanently lost, and `session_token` changes. This never raises. An anonymous pre-login session carries no authorization, so re-minting crosses no trust boundary.
4. Any other error, raised as a typed exception. No swallow, no auto-retry beyond the one re-mint in step 3.

## Logging Out

```python
await server_client.anonymous.logout(store_options=store_options)
```

> [!CAUTION]
> **`logout()` does not revoke.** There is no server-side anonymous session store to revoke against, this clears only the locally-held encrypted context. Any access token already issued for this anonymous session remains valid until its natural expiry.

Authenticated (OIDC) logout also ends an active anonymous session. When you call `ServerClient.logout()` and an anonymous store is configured, the SDK clears the locally-held anonymous session before returning the logout URL. This is a local clear only, with no remote call (consistent with `anonymous.logout()`, which also does not revoke server-side). It prevents the next visitor on a shared device from having the previous visitor's anonymous identity re-linked at their login. If no anonymous session is active, nothing is cleared.

## Login Injection

When an anonymous session is active, `start_interactive_login()` automatically injects an `anon_transfer_token` transfer ticket into the `/authorize` URL, no code change needed at your call site. If no anonymous session exists, behavior is unchanged.

The raw `session_token` never goes on the URL. At the moment the `/authorize` URL is built, the SDK exchanges the stored session token for a short-lived (30s) single-use ticket (`anon_transfer_token`) via `POST /anonymous/token`, and forwards only that ticket as the `anon_transfer_token` query parameter. The raw session token stays inside the SDK's encrypted store and the ticket is never persisted. The ticket is short-lived and grants no authorization on its own, but you should still set `Referrer-Policy: no-referrer` on your login pages and never log the authorize URL.

The exchange fails open: if it errors (network failure, a non-200, or an unparseable response), login proceeds with no ticket and no linking, and never aborts the login.

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
)

try:
    session = await server_client.anonymous.create_session(audience="...", scope="...")
except AnonymousSessionFeatureNotEnabledError:
    ...
```
