# Passwordless Authentication

Passwordless lets users sign in with a one-time code sent by email or SMS, or with a magic link sent by email. This guide covers the **embedded login** flow on `ServerClient.passwordless` and how each path establishes a server-side session.

> [!NOTE]
> Passwordless API flows use Auth0 Legacy Passwordless connections (`email` and `sms`). Enable the **Passwordless OTP** grant for your application under **Applications -> Your App -> Advanced Settings -> Grant Types**. See the [Auth0 Passwordless API documentation](https://auth0.com/docs/authenticate/passwordless/implement-login/embedded-login/relevant-api-endpoints).

> [!IMPORTANT]
> These flows are for confidential server-side applications. Tokens stay on the server; the browser should only receive your application's session cookie or opaque session reference.

## Table of Contents

- [How the flow works](#how-the-flow-works)
- [Prerequisites](#prerequisites)
- [1. Email OTP](#1-email-otp)
- [2. SMS OTP](#2-sms-otp)
- [3. Email magic link](#3-email-magic-link)
- [4. Custom scopes and audiences](#4-custom-scopes-and-audiences)
- [5. Forwarding the end-user IP](#5-forwarding-the-end-user-ip)
- [Completing MFA during passwordless login](#completing-mfa-during-passwordless-login)
- [Error Handling](#error-handling)

## How the flow works

Passwordless has two shapes:

1. **OTP code** - `start()` sends a code by email or SMS. Your app collects that code, then `verify()` exchanges it at `/oauth/token` with the passwordless OTP grant and **creates a server-side session**.
2. **Magic link** - `start(send="link")` sends a one-click email link. Auth0 redirects the user back to your callback URL, and your app completes the flow with `complete_interactive_login()`. The callback creates the server-side session.

OTP start does **not** create a session. The session exists only after `verify()` succeeds. Magic-link start writes a transaction so the callback can validate the returned `state`; the session exists only after the callback completes.

## Prerequisites

These flows require a **Regular Web Application** — passwordless token exchange
needs a client secret, which a public/SPA client cannot hold safely.

Two tenant-level settings are also required and are easy to miss because
neither failure mode looks like a configuration problem:

1. **Authentication Profile must be "Identifier First."** The default
   "Universal Login" profile blocks the direct `/oauth/token` call this SDK
   uses for OTP verification — without it, OTP `verify()` fails with
   `unauthorized_client`. Set it under your tenant's Authentication Profile
   settings. (Skip this if you only use passwordless via Universal Login
   redirects rather than this SDK's embedded flow.)
2. **Enable the Passwordless OTP grant type** on your application
   (**Applications -> Your App -> Advanced Settings -> Grant Types**). Without
   it, OTP verification also fails with `unauthorized_client`.
3. **Magic link only** — set the tenant flag
   `universal_login.passwordless.allow_magiclink_verify_without_session` to
   `true` via the Management API:

   ```
   PATCH /api/v2/tenants/settings
   { "universal_login": { "passwordless": { "allow_magiclink_verify_without_session": true } } }
   ```

   This is required for **any** server-side SDK completing magic link (this
   one, Express, Next.js, etc.) — the browser that opens the emailed link is
   not guaranteed to be the same browser/session that started the flow.
   Without it, the user sees: *"The link must be opened on the same device
   and browser from which you submitted your email address."* This flag is
   not documented in the public Auth0 API reference, so if you don't set it
   here you will not discover it from a 400 error message.

```python
from auth0_server_python.auth_server.server_client import ServerClient

server_client = ServerClient(
    domain="YOUR_AUTH0_DOMAIN",
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    secret="YOUR_SECRET",
    redirect_uri="https://app.example.com/auth/callback",
)
```

For apps using request/response-backed stores or multiple custom domains, pass `store_options={"request": request, "response": response}` to each method that reads or writes transaction/session state.

## 1. Email OTP

### Step 1 - Send the code

```python
from auth0_server_python.auth_types import StartPasswordlessEmailOptions

start_result = await server_client.passwordless.start(
    StartPasswordlessEmailOptions(
        email="user@example.com",
        send="code",
        language="en-US",  # optional x-request-language header
    ),
    store_options={"request": request, "response": response},
)

# start_result.id is Auth0's request identifier when returned by the API.
```

### Step 2 - Verify the code and establish the session

```python
from auth0_server_python.auth_types import VerifyPasswordlessOtpOptions

result = await server_client.passwordless.verify(
    VerifyPasswordlessOtpOptions(
        connection="email",
        email="user@example.com",
        verification_code=user_entered_code,
    ),
    store_options={"request": request, "response": response},
)

user = result["state_data"]["user"]
print(f"Signed in: {user['sub']}")
```

The SDK verifies the returned ID token, validates the issuer and audience, persists the tokens in the configured state store, and sources the session `sid` from the verified ID token when available.

## 2. SMS OTP

SMS has the same two-step shape. Phone numbers must be in E.164 format.

```python
from auth0_server_python.auth_types import (
    StartPasswordlessSmsOptions,
    VerifyPasswordlessOtpOptions,
)

await server_client.passwordless.start(
    StartPasswordlessSmsOptions(
        phone_number="+14155550100",
    ),
    store_options={"request": request, "response": response},
)

result = await server_client.passwordless.verify(
    VerifyPasswordlessOtpOptions(
        connection="sms",
        phone_number="+14155550100",
        verification_code=user_entered_code,
    ),
    store_options={"request": request, "response": response},
)
```

By default, email OTP requests `openid profile email`; SMS OTP requests `openid profile` because SMS identities do not have an email claim to satisfy.

## 3. Email magic link

Magic links are email-only. `start(send="link")` persists a transaction and includes SDK-owned `redirect_uri`, `response_type`, and `state` in Auth0's `authParams`.

```python
from auth0_server_python.auth_types import StartPasswordlessEmailOptions

await server_client.passwordless.start(
    StartPasswordlessEmailOptions(
        email="user@example.com",
        send="link",
        auth_params={
            "scope": "openid profile email",
            "login_hint": "user@example.com",
        },
    ),
    store_options={"request": request, "response": response},
)
```

> [!IMPORTANT]
> Magic-link start requires `store_options` whenever your transaction store needs the framework request/response to write state. Without that transaction, the callback cannot validate the returned `state`.

When the user clicks the emailed link, Auth0 redirects back to your configured callback URL. Complete it with the standard interactive-login callback:

```python
callback_url = str(request.url)

result = await server_client.complete_interactive_login(
    callback_url,
    store_options={"request": request, "response": response},
)

user = result["state_data"]["user"]
```

> [!WARNING]
> Do not let callers override `redirect_uri`, `state`, `response_type`, `nonce`, or PKCE fields in magic-link `auth_params`. The SDK owns these values so the emailed authorization code and state cannot be redirected to an attacker-controlled URL.
>
> This matters more than it looks: Auth0 treats magic-link `state` as a pure echo and does not validate it server-side, and the clicked link's query string can overwrite whatever the browser originally stored. The SDK's single-use, `state`-keyed transaction plus the exact-match `redirect_uri` are therefore the *entire* CSRF / authorization-code-interception defense on this flow — Auth0 will not catch a bypass for you.

## 4. Custom scopes and audiences

For OTP flows, pass `scope` and `audience` to `verify()`. These become the `/oauth/token` request parameters.

```python
result = await server_client.passwordless.verify(
    VerifyPasswordlessOtpOptions(
        connection="email",
        email="user@example.com",
        verification_code=user_entered_code,
        audience="https://api.example.com",
        scope="openid profile email offline_access read:orders",
    ),
    store_options={"request": request, "response": response},
)
```

For magic links, pass allowed authorization parameters through `auth_params` at `start()` time:

```python
await server_client.passwordless.start(
    StartPasswordlessEmailOptions(
        email="user@example.com",
        send="link",
        auth_params={
            "audience": "https://api.example.com",
            "scope": "openid profile email offline_access read:orders",
            "login_hint": "user@example.com",
        },
    ),
    store_options={"request": request, "response": response},
)
```

A caller-supplied magic-link `scope` **replaces** the default wholesale rather than merging with it. The SDK re-injects `openid` when your scope omits it, because the magic-link callback would otherwise complete on a token response carrying no ID token — a session built from claims nothing verified. `openid` is never duplicated and your scope order is preserved otherwise.

> [!NOTE]
> `state` is intentionally not a caller-supplied auth parameter in this SDK. If you need app-specific return data, store it server-side against your own transaction/session context instead of putting it into the Auth0 magic-link `state`.

## 5. Forwarding the end-user IP

Auth0 attack protection and rate limiting normally see the IP address of the server making the API call. For confidential clients, Auth0 can use the `auth0-forwarded-for` header when the **Trust Token Endpoint IP Header** setting is enabled.

```python
await server_client.passwordless.start(
    StartPasswordlessEmailOptions(
        email="user@example.com",
        send="code",
        client_ip=request.client.host,
    ),
    store_options={"request": request, "response": response},
)

result = await server_client.passwordless.verify(
    VerifyPasswordlessOtpOptions(
        connection="email",
        email="user@example.com",
        verification_code=user_entered_code,
        client_ip=request.client.host,
    ),
    store_options={"request": request, "response": response},
)
```

> [!WARNING]
> Only forward a trusted, normalized end-user IP from your edge/proxy layer. Do not blindly copy arbitrary client-supplied headers into `client_ip`.

## Completing MFA during passwordless login

Auth0 can require MFA during passwordless OTP verification. In that case, the SDK raises `MfaRequiredError` before it creates a session. Complete the MFA challenge with `server_client.mfa`, then persist the returned tokens according to your framework's session integration.

```python
from auth0_server_python.error import MfaRequiredError

try:
    result = await server_client.passwordless.verify(
        VerifyPasswordlessOtpOptions(
            connection="email",
            email="user@example.com",
            verification_code=user_entered_code,
        ),
        store_options={"request": request, "response": response},
    )
    user = result["state_data"]["user"]

except MfaRequiredError as e:
    await server_client.mfa.challenge_authenticator(
        {"mfa_token": e.mfa_token, "factor_type": "otp"},
        store_options={"request": request, "response": response},
    )

    verify_response = await server_client.mfa.verify(
        {"mfa_token": e.mfa_token, "otp": mfa_code},
        store_options={"request": request, "response": response},
    )

    save_session_for_user(
        access_token=verify_response.access_token,
        id_token=verify_response.id_token,
        refresh_token=verify_response.refresh_token,
    )
```

> [!NOTE]
> Passwordless OTP MFA is like passkey-first MFA: there is no existing application session yet. Use the returned MFA tokens to create the session in your framework layer rather than trying to update a session that does not exist.

## Error Handling

Passwordless methods raise typed SDK errors:

- `PasswordlessStartError` - `POST /passwordless/start` failed
- `PasswordlessVerifyError` - OTP token exchange or ID-token verification failed, including an issuer or audience mismatch (`invalid_issuer` / `invalid_audience`)
- `MfaRequiredError` - Auth0 requires MFA before completing login
- `MissingRequiredArgumentError` - required SDK input is missing, such as magic-link `store_options`
- `InvalidArgumentError` - caller input is rejected before a network call

### Basic handling

```python
from auth0_server_python.error import Auth0Error

try:
    result = await server_client.passwordless.verify(
        VerifyPasswordlessOtpOptions(
            connection="email",
            email="user@example.com",
            verification_code=user_entered_code,
        ),
        store_options={"request": request, "response": response},
    )
except Auth0Error as e:
    return {"error": str(e)}
```

### Advanced handling

```python
from auth0_server_python.error import (
    Auth0Error,
    MfaRequiredError,
    PasswordlessStartError,
    PasswordlessVerifyError,
)

try:
    result = await server_client.passwordless.verify(
        VerifyPasswordlessOtpOptions(
            connection="email",
            email="user@example.com",
            verification_code=user_entered_code,
        ),
        store_options={"request": request, "response": response},
    )
except MfaRequiredError as e:
    return start_mfa(e.mfa_token)
except PasswordlessVerifyError as e:
    return {"error": e.code, "detail": e.message, "retry_after": e.retry_after}
except PasswordlessStartError as e:
    return {"error": e.code, "detail": e.message, "retry_after": e.retry_after}
except Auth0Error as e:
    return {"error": str(e)}
```

`PasswordlessStartError` and `PasswordlessVerifyError` both carry:

- `code` / `message` - the Auth0 `error` and `error_description`, or an SDK-side code when the response had neither
- `error` / `error_description` - the raw values from a JSON error body
- `retry_after` - seconds from the `Retry-After` response header, typically on a 429. `None` when the header is absent or in HTTP-date form (which the SDK does not interpret)
- `cause` - the parsed JSON error body, or the response text truncated to 2048 characters when the body was not JSON

> [!WARNING]
> `cause` may hold a raw upstream body (an HTML error page, WAF block page, or proxy dump). It is length-capped, but not redacted — do not log it at a level where untrusted upstream content is unwelcome.

Because a 429 that carries an explicit Auth0 `error` reports that server code, `code == "too_many_requests"` is not a reliable rate-limit predicate. Branch on `retry_after is not None`, or on the HTTP status if you need certainty.

### Common error codes (`PasswordlessErrorCode`)

- `bad.connection` - the passwordless connection is disabled or invalid
- `bad.email` - the email address is invalid or rejected by Auth0
- `sms_provider_error` - Auth0 could not send the SMS
- `too_many_requests` - rate limiting or attack protection blocked the request (`start()` or `verify()`)
- `invalid_grant` - the OTP is invalid, expired, or already used
- `invalid_issuer` - returned ID token issuer does not match your configured Auth0 domain
- `invalid_audience` - returned ID token audience does not match the SDK client
- `discovery_error` - the SDK could not load authorization server metadata
- `passwordless_start_failed` - SDK-side start failure
- `passwordless_verify_failed` - SDK-side verify failure
