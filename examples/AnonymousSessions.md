# Anonymous Sessions

Anonymous Sessions give a visitor an Auth0 identity **before they log in**. Each visitor gets a persistent `anon@<uuid>` subject plus an access token, with up to 1 KB of key/value metadata (cart, preferences) attached at creation. At login, the session token rides into `/authorize` so Post-Login / Pre-User-Registration Actions can read the anonymous data via `event.anonymous_session` — nothing migrates onto the real user profile automatically; the Action author decides what to persist.

> [!NOTE]
> Anonymous Sessions support for server SDKs is in Early Access, gated by a tenant-level, paid add-on feature flag (`anonymous_sessions_enabled`). `auth0-server-python` mounts no routes and sets no cookies — this guide covers the framework-agnostic core only.

## Table of Contents

- [Anonymous Sessions](#anonymous-sessions)
  - [Table of Contents](#table-of-contents)
  - [Setup](#setup)
  - [The Anonymous Store — Read This Before Configuring Anything](#the-anonymous-store--read-this-before-configuring-anything)
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
    anonymous_store=my_anonymous_store,   # see below — read before wiring this up
)
```

## The Anonymous Store — Read This Before Configuring Anything

> [!WARNING]
> **`anonymous_store` MUST be a distinct store *instance* from `state_store` — not merely a different identifier passed to the same instance.**
>
> On the default `auth0-fastapi` cookie-backed stores (`StatelessStateStore`, `CookieTransactionStore`), the `identifier` argument to `set`/`get`/`delete` is used **only as an encryption salt** — the physical cookie name comes from the store instance's own `cookie_name`, fixed at construction. Two different identifiers written through the *same* store instance land on the *same* cookie and collide: the second write overwrites the first, and the failed decrypt on the next read is silently swallowed. Concretely, if you point `anonymous_store` at the same instance as `state_store`:
>
> - **Anonymous session created, then user logs in:** the login overwrites the anonymous session's cookie. The anonymous context is gone — the `sub`/metadata correlation this feature exists to deliver silently never happens.
> - **User logged in, then an anonymous session is created on the same request cycle:** the anonymous write overwrites the authenticated session's cookie. The next `get_session()` call decrypts garbage, returns `None`, and **the user is silently logged out** — no exception, no log line.
>
> Give `anonymous_store` its own `cookie_name` (or key prefix, or table) — a different construction, not a different string passed to the same one. If you omit `anonymous_store` entirely, every `.anonymous.*` call raises `ConfigurationError` immediately, before any write — it never falls back to `state_store`.

This is not a hypothetical: it is the same root cause already live in this SDK's own `MfaClient`, which writes a second identifier (`_a0_mfa_pending`) into the shared state store today. If you are implementing a custom store, treat `identifier` as a value your store must resolve to a genuinely distinct record — not merely a distinct encryption salt on a fixed location.

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
> **Always check `is_new`.** It is `True` both on the first call to `create_session()` and on a *silent* re-mint (see below) — the only signal your application receives when the anonymous `sub` has changed. Any code correlating data on `sub` (e.g. a cart keyed by anonymous user) must check this on every call, not just the first.

## Getting a Token (Renewal Ladder)

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

> [!CAUTION]
> **This return shape is provisional.** The platform has not finalized what fields `/anonymous/userinfo` returns. The SDK's `AnonymousSessionIntrospection` model declares only `sub`, `session_id`, `expires_at`, and `metadata`, and ignores anything else in the response — a follow-up SDK release adding fields here is expected, not a breaking change. `introspect()` is a pure read: it never triggers the renewal ladder and never writes to the store on the SDK side. Whether the platform's own endpoint re-mints server-side as a side effect of being called is unconfirmed — treat that as a caveat if you observe it, not an SDK guarantee either way.

## Logging Out

```python
await server_client.anonymous.logout(store_options=store_options)
```

> [!CAUTION]
> **`logout()` does not revoke.** There is no server-side anonymous session store to revoke against — this clears only the locally-held encrypted context. Any access token already issued for this anonymous session remains valid until its natural expiry.

## Login Injection

When an anonymous session is active, `start_interactive_login()` automatically includes the session token in the `/authorize` request — no code change needed at your call site. If no anonymous session exists, behavior is byte-identical to today. If the stored anonymous token is malformed or undecryptable, the link is silently dropped and the login proceeds normally — a broken anonymous session never blocks login.

The session token is **only ever sourced from the SDK's own encrypted anonymous store** — there is no public API through which a caller can supply one directly, and any attempt to smuggle one in via `authorization_params` (constructor or per-call) is stripped before the request is built. This is deliberate: it closes a session-fixation vector where an attacker's anonymous session could otherwise be linked onto a victim's fresh login.

The token travels as a query parameter to `/authorize`, which means it lands in browser history, `Referer` headers, and access logs. This is accepted because the token grants no authorization on its own and the request is a browser-to-Auth0 HTTPS redirect — but you should still set `Referrer-Policy: no-referrer` on your login pages, and never log the authorize URL.

Pushed Authorization Requests (PAR) are not supported for anonymous sessions — injection is suppressed entirely on that code path.

## Rate-Limiting `get_token()`

`get_token()`'s retry-once bound caps amplification to two upstream Auth0 calls *per invocation* — it does not protect against an attacker calling your route repeatedly. `POST /anonymous/token` is an unauthenticated, token-issuing endpoint. **You must rate-limit any route in your application that calls `get_token()` on an anonymous session**, the same way you would rate-limit any other unauthenticated token-issuing path. The SDK has no request-level context to do this itself.

## Error Handling

All anonymous session errors subclass `AnonymousApiError`, carrying a `.code` you can branch on:

```python
from auth0_server_python.error import (
    AnonymousFeatureNotEnabledError,   # tenant flag is off
    AnonymousClientNotEnabledError,    # client not enabled for anonymous sessions
    AnonymousClientNotSupportedError,  # e.g. a DPoP-mandated client — see Known Limitations
    AnonymousResourceServerError,      # audience not a valid/enabled resource server
    AnonymousScopeError,               # scope not granted to anonymous callers
    AnonymousSessionCreateError,       # base class for create/re-mint failures
    AnonymousTokenError,               # get_token() failure with no active session
    AnonymousSessionIntrospectError,
    AnonymousLogoutError,
)

try:
    session = await server_client.anonymous.create_session(audience="...", scope="...")
except AnonymousFeatureNotEnabledError:
    # tenant configuration problem — not a code bug
    ...
```

`.cause` is scrubbed of `client_secret`, `session_token`, `access_token`, and related fields recursively before it is stored, so it is always safe to log.

## Known Limitations

- **Metadata is attacker-authored, pre-auth input.** By the time a Post-Login Action reads `event.anonymous_session.metadata`, it is untrusted data from an unauthenticated caller. The SDK validates size and rejects dangerous keys, but your Action author is responsible for validating content before trusting or persisting it.
- **Single audience per session.** `get_token()` takes no `audience` parameter — one anonymous session serves exactly one audience. To call two APIs anonymously, create two sessions (and accept that each has independent metadata and lifecycle).
- **DPoP is not supported.** `AnonymousClient` has no `dpop_key` parameter anywhere in its public API — this is a structural exclusion, not a runtime check. A tenant/client configured with `require_proof_of_possession: true` cannot use anonymous sessions; you will see `AnonymousClientNotSupportedError`.
- **PAR, CIBA, Device Flow, RAR, and mTLS clients are not supported** for anonymous sessions.
- **Multiple Custom Domains (MCD):** the SDK gates on domain to prevent an anonymous session minted against one tenant being served on a resolver call for a different tenant — a mismatch silently mints a fresh session under the current tenant rather than serving cross-tenant state.
- **No server-side revocation.** See [Logging Out](#logging-out) above.

## Additional Resources

- [MFA.md](MFA.md) — anonymous sessions are unrelated to MFA and never interact with it.
- [ConfigureStore.md](ConfigureStore.md) — general store implementation guidance; anonymous sessions add the distinct-instance requirement above on top of everything there.
- [MultipleCustomDomains.md](MultipleCustomDomains.md) — background on the resolver-mode domain gating referenced above.
