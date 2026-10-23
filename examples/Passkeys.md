# Passkey Authentication

Passkeys let users sign up and log in with [WebAuthn](https://www.w3.org/TR/webauthn-2/) credentials (Touch ID, Face ID, Windows Hello, or a hardware security key) instead of a password. This guide covers the **primary authentication** flow on `ServerClient` - signing a user up or in with a passkey and establishing a server-side session.

> [!NOTE]
> Passkeys require a [Custom Domain](https://auth0.com/docs/customize/custom-domains) (WebAuthn binds the credential to the relying-party domain) and the native passkey feature enabled on your tenant. See the [Auth0 passkey documentation](https://auth0.com/docs/authenticate/database-connections/passkeys).

> [!NOTE]
> Managing a logged-in user's enrolled passkeys (enroll a new passkey, list, rename, delete) is a **separate** surface on the My Account API. See [examples/MyAccountAuthenticationMethods.md](MyAccountAuthenticationMethods.md).

## Table of Contents

- [How the flow works](#how-the-flow-works)
- [Prerequisites](#prerequisites)
- [1. Passkey Signup](#1-passkey-signup)
- [2. Passkey Login](#2-passkey-login)
- [3. DPoP-bound passkey tokens (optional)](#3-dpop-bound-passkey-tokens-optional)
  - [Completing MFA on a passkey login (and where the session comes from)](#completing-mfa-on-a-passkey-login-and-where-the-session-comes-from)
- [4. Identifier verification (optional)](#4-identifier-verification-optional)
- [Error Handling](#error-handling)

## How the flow works

A passkey ceremony is always **two steps**, because the WebAuthn signature happens in the browser between them:

1. **Challenge** - the SDK asks Auth0 for a challenge (`passkey_signup_challenge` / `passkey_login_challenge`). Auth0 returns an `auth_session` and the WebAuthn options (`authn_params_public_key`).
2. **Browser** - your front end passes those options to `navigator.credentials.create()` (signup) or `navigator.credentials.get()` (login). The authenticator produces a signed credential.
3. **Verify / sign-in** - the SDK exchanges the signed credential for tokens (`signin_with_passkey`) and **creates a server-side session**, exactly like every other login path.

## Prerequisites

```python
from auth0_server_python.auth_server.server_client import ServerClient

# Passkey sign-in persists a server-side session, and the challenge step stores
# short-lived transaction data, so ServerClient needs a state store and a
# transaction store (it does not create defaults). If your framework wrapper
# (e.g. auth0-fastapi) already provides these, reuse them. Otherwise, create
# your own implementations of the StateStore / TransactionStore ABCs.
state_store = YourStateStore(...)              # or the store your framework provides
transaction_store = YourTransactionStore(...)  # or the store your framework provides

server_client = ServerClient(
    domain="YOUR_CUSTOM_DOMAIN",
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    secret="YOUR_SECRET",
    state_store=state_store,
    transaction_store=transaction_store,
)
```

For store implementations (cookie, Redis, database) and how to pass `store_options`, see [examples/ConfigureStore.md](ConfigureStore.md).

The **Passkey** grant (`urn:okta:params:oauth:grant-type:webauthn`) must be enabled for your application under **Applications → Your App → Grant Types**.

> [!NOTE]
> The passkey challenge endpoints accept a client secret only, not a client assertion. A client configured with just a `client_assertion_signing_key` (Private Key JWT) cannot use the passkey flows, so configure a `client_secret` to use them.

## 1. Passkey Signup

### Step 1 - Request a signup challenge

```python
from auth0_server_python.auth_types import PasskeyUserProfile

challenge = await server_client.passkey_signup_challenge(
    user_profile=PasskeyUserProfile(
        email="new.user@example.com",
        name="Jane Doe",
        username="jane.doe",
        phone_number="+15551234567",
        given_name="Jane",
        family_name="Doe",
        nickname="Janie",
        picture="https://example.com/jane.png",
    ),
    connection="Username-Password-Authentication",  # optional database connection (realm)
    store_options={"request": request, "response": response},
)

# Hand these to the browser:
#   challenge.auth_session              -> opaque session credential (Tier 1, do not log)
#   challenge.authn_params_public_key   -> pass to navigator.credentials.create()
#   challenge.verification_required     -> codes to collect first, when set (see section 4)
# auth_session does not appear in print(challenge). To inspect it while debugging, read challenge.auth_session.
```

> [!TIP]
> `PasskeyUserProfile` allows extra fields - any additional profile attribute your tenant accepts (for example `given_name`, `family_name`, `picture`) passes through without an SDK change. Pass tenant-specific custom data via the separate `user_metadata` argument.

### Step 2 - Create the credential in the browser

Pass `authn_params_public_key` to `navigator.credentials.create()`. The resulting credential serializes to the shape the SDK expects in step 3 (`id`, `rawId`, `type`, and a `response` object with `clientDataJSON` + `attestationObject`).

### Step 3 - Verify and establish the session

```python
from auth0_server_python.auth_types import PasskeyAuthResponse

result = await server_client.signin_with_passkey(
    auth_session=challenge.auth_session,
    authn_response=PasskeyAuthResponse(
        id=credential["id"],
        raw_id=credential["rawId"],          # accepts rawId alias too
        type="public-key",
        response={
            "clientDataJSON": credential["response"]["clientDataJSON"],
            "attestationObject": credential["response"]["attestationObject"],
        },
    ),
    store_options={"request": request, "response": response},
)

user = result.state_data["user"]
```

`signin_with_passkey` returns a `PasskeyLoginResult` whose `state_data` holds the user claims and token sets - the same shape as `complete_interactive_login` and `login_with_custom_token_exchange`. The session is persisted to your configured state store.

> [!NOTE]
> If your connection requires users to verify their email or phone at signup, `passkey_signup_challenge` also accepts a `delivery_method` and `signin_with_passkey` accepts a `verification` argument. Both are optional and covered in [section 4](#4-identifier-verification-optional).

## 2. Passkey Login

Identical shape, different endpoints. The browser uses `navigator.credentials.get()` and the user picks a passkey from the prompt. That credential identifies the user, so the login challenge takes no username.

```python
# Step 1 - login challenge
challenge = await server_client.passkey_login_challenge(
    connection="Username-Password-Authentication",   # optional
    store_options={"request": request, "response": response},
)

# Step 2 - browser: navigator.credentials.get(challenge.authn_params_public_key)

# Step 3 - sign in. The login credential's response carries
# clientDataJSON + authenticatorData + signature + userHandle.
result = await server_client.signin_with_passkey(
    auth_session=challenge.auth_session,
    authn_response=PasskeyAuthResponse(
        id=credential["id"],
        raw_id=credential["rawId"],
        type="public-key",
        response={
            "clientDataJSON": credential["response"]["clientDataJSON"],
            "authenticatorData": credential["response"]["authenticatorData"],
            "signature": credential["response"]["signature"],
            "userHandle": credential["response"]["userHandle"],
        },
    ),
    store_options={"request": request, "response": response},
)
```

> [!NOTE]
> The SDK is transparent to the signup-vs-login difference in the credential `response` - both flow through the same `PasskeyAuthResponse.response` dict. Send exactly the keys the browser produced.

## 3. DPoP-bound passkey tokens (optional)

Pass an optional `dpop_key` to bind the issued tokens to a key your server holds ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)), so a stolen token alone cannot be replayed. DPoP is **opt-in**: omit `dpop_key` and sign-in returns ordinary Bearer tokens with no behaviour change.

```python
from jwcrypto import jwk

dpop_key = jwk.JWK.generate(kty="EC", crv="P-256")  # you generate and keep this key

result = await server_client.signin_with_passkey(
    auth_session=challenge.auth_session,
    authn_response=authn_response,
    dpop_key=dpop_key,
    store_options={"request": request, "response": response},
)
```

When `dpop_key` is supplied, the SDK attaches a token-endpoint proof so Auth0 issues a DPoP-bound token, transparently handles the server-nonce challenge, and **rejects a Bearer downgrade** - if the server returns an unbound token, `signin_with_passkey` raises `PasskeyError` rather than silently accepting a token bound to a key it never used.

> [!TIP]
> Reuse the **same** `dpop_key` for any subsequent My Account API calls made with the resulting token - the token is bound to that one key. See [MyAccountAuthenticationMethods.md → DPoP](MyAccountAuthenticationMethods.md#dpop).

> [!WARNING]
> The `dpop_key` private key is a **secret**. Keep it in your secret store (KMS/HSM), never log it (`repr()` is redacted, but `key.export_private()` is not), use **one key per user/session** (never share across principals), and use **EC P-256 only** - any other key type fails closed with a `ValueError` before any network call.

### Completing MFA on a passkey login (and where the session comes from)

When a passkey login needs a second factor, `signin_with_passkey` raises `MfaRequiredError` **before** it creates a session. You finish the login by challenging and verifying through `client.mfa`, then **store the returned tokens yourself** - on this path the SDK does not persist the session for you (`persist` defaults to `False`, and there is no existing session to update yet):

```python
from auth0_server_python.error import MfaRequiredError

try:
    result = await server_client.signin_with_passkey(
        auth_session=auth_session,
        authn_response=authn_response,
        dpop_key=dpop_key,                     # optional, omit for Bearer tokens
        store_options={"request": request, "response": response},
    )
    # No MFA needed: signin_with_passkey already persisted the session for you.
    user = result.state_data["user"]

except MfaRequiredError as e:
    # 1. Challenge the factor (e.g. an authenticator-app OTP).
    await server_client.mfa.challenge_authenticator(
        {"mfa_token": e.mfa_token, "factor_type": "otp"},
        store_options={"request": request, "response": response},
    )

    # 2. Verify the user's code. Re-supply the SAME dpop_key so the issued
    #    token stays DPoP-bound. persist=False (the default) → the SDK returns
    #    the tokens instead of writing a session.
    verify_response = await server_client.mfa.verify(
        {"mfa_token": e.mfa_token, "otp": otp_code},
        dpop_key=dpop_key,                     # same key given to signin_with_passkey
        store_options={"request": request, "response": response},
    )

    # 3. Persist the tokens into YOUR session yourself - this is the step the
    #    SDK skips on the MFA path because no session existed at login time.
    save_session_for_user(
        access_token=verify_response.access_token,
        id_token=verify_response.id_token,
        refresh_token=verify_response.refresh_token,
    )
```

> [!IMPORTANT]
> Re-supply the **same** `dpop_key` to `verify`. Omitting it when the login was DPoP-bound would downgrade the result to a Bearer token; `verify` **rejects** that mismatch with `MfaVerifyError` rather than silently dropping the sender constraint. DPoP is preserved end to end - `persist=False` affects only *who writes the session*, never the token binding.

> [!NOTE]
> Do **not** pass `persist=True` on this path. It updates an *existing* session, and a passkey-first login has none yet, so it raises `MfaVerifyError("No existing session found…")` - discarding the tokens `verify` just obtained. Use `persist=False` and store the returned tokens as shown above.

## 4. Identifier verification (optional)

When a connection requires users to verify their email or phone number at signup, the signup challenge lists the identifiers that need a code, Auth0 sends each code, and you pass the codes to `signin_with_passkey`. Connections without verification follow the flow in section 1.

### Requirements

Enable identifier verification for email, phone, or both on your database connection. For email, choose the One-Time Password (OTP) method, because this flow passes codes and does not support verification links.

- Configure an email provider for email codes and a phone provider for phone codes. Without one the code is never sent, so the user can't finish signing up.
- Upgrade your app to an SDK version whose `signin_with_passkey` accepts `verification` before you turn verification on. Older versions can't send the codes, so every signup on the connection fails.

### The flow

1. Request the challenge. If `verification_required` is set, collect a code for each identifier it lists.
2. Collect the codes before creating the credential, so a user who never receives a code doesn't end up with a passkey for an account that was never created. This order is a UX requirement, and the SDK can't enforce it. Your front end must not call `navigator.credentials.create()` until every required code is collected. Auth0 checks the codes only in `signin_with_passkey`, after the credential exists, so a wrong code still leaves a passkey on the device with no account behind it. The retry reuses that credential.
3. Create the credential in the browser, then call `signin_with_passkey` with the codes in `verification`.

```python
challenge = await server_client.passkey_signup_challenge(
    user_profile=PasskeyUserProfile(email="new.user@example.com", phone_number="+15551234567"),
    delivery_method="text",   # optional, "text" or "voice" for the phone code
    store_options={"request": request, "response": response},
)

# For example ["email", "phone"], or None when nothing needs verifying
required = challenge.verification_required

result = await server_client.signin_with_passkey(
    auth_session=challenge.auth_session,
    authn_response=authn_response,
    verification={"email": email_code, "phone": phone_code},
    store_options={"request": request, "response": response},
)
```

`verification` must be a dict whose keys are `email` or `phone`, as listed in `verification_required`, and whose values are strings. Anything else raises `InvalidArgumentError` before any request is sent. Blank codes are ignored. Omit `verification` when `verification_required` is `None`.

`delivery_method` applies only to the phone code. If only email needs a code, the value has no effect. Any value other than `"text"` or `"voice"` raises `InvalidArgumentError` before the request is sent.

### Resending codes

If the user does not receive a code, call `passkey_signup_challenge` again before the passkey is created. Each call sends new codes for every identifier and returns a new `auth_session` and new `authn_params_public_key`, so use the values from the latest response. The previous session stays valid until it expires.

### Handling a wrong code

After a wrong code the session stays valid. `signin_with_passkey` raises a `PasskeyError` with `is_verification_retryable` set to `True`, and its `verification_required` lists the identifiers still unverified.

Each attempt is one HTTP request. On a wrong code, the handler returns `verification_required` and the `auth_session` from the error. The browser asks for those codes only and posts again with the same credential. Cap the attempts in your app, because Auth0 also limits them.

```python
from fastapi.responses import JSONResponse

from auth0_server_python.error import PasskeyError

async def passkey_signin(request, response, body):
    try:
        await server_client.signin_with_passkey(
            auth_session=body["auth_session"],
            authn_response=body["authn_response"],
            verification=body.get("verification"),
            store_options={"request": request, "response": response},
        )
    except PasskeyError as e:
        if not e.is_verification_retryable:
            raise
        # Send the unverified identifiers back so the page asks only for those codes.
        return JSONResponse(
            {"verification_required": e.verification_required, "auth_session": e.auth_session},
            status_code=400,
        )
    # The result holds the tokens, so keep it on the server.
    return {"signed_in": True}
```

Send one `signin_with_passkey` request at a time per `auth_session`. Parallel requests can use up the allowed attempts, or reach Auth0 after the session has already been used.

`is_verification_retryable` is `False` in these cases.

- Too many wrong codes, an expired code, or an expired session. Start again from the signup challenge.
- A missing code raises `invalid_request` and the session stays valid. Resubmit with the same `auth_session` and every required code.
- A server error sets `status_code` to 500 or higher. `code` is the response body's `error`, or `passkey_token_error` when there is none.
- A rate limit (`status_code` is 429). Auth0 rejects the request before it uses the attempt, so wait and resend the same request with the same `auth_session`, `authn_response` and codes. When `retry_after` is set, wait that many seconds. Check `status_code`, not `code`, because the code depends on which limit was hit.
- Any other failure is raised with the `error` code Auth0 returned, or `passkey_token_error` when the response has no JSON error body.

If the connection drops after Auth0 accepts the final code, or a Post Login Action denies the login, the account may already exist, because Auth0 creates the user before Actions run. A new signup with the same email then fails with `invalid_request`. Show a generic message that offers sign in, without confirming whether the account exists. `invalid_request` also covers invalid input, so don't treat it alone as proof that the account exists.

### Operational notes

- Rate-limit the route that calls `passkey_signup_challenge`. Each call sends codes, so add limits per IP address and per email address or phone number.
- Pass `client_ip` to `passkey_signup_challenge`, `passkey_login_challenge` and `signin_with_passkey` to forward the end user's IP address as the `auth0-forwarded-for` header. Without it Auth0 sees your server's address. Auth0 uses the header when the **Trust Token Endpoint IP Header** setting is enabled for the application, and, while identifier verification is enabled for your tenant, it rejects a value that is not a valid IP address. Forward only a trusted, normalized IP from your edge or proxy layer.
- Do not log the verification codes.

> [!IMPORTANT]
> If your tenant requires DPoP, pass `dpop_key` to `signin_with_passkey` as described in section 3.

## Error Handling

The three passkey methods raise `PasskeyError`, a subclass of `Auth0Error`. Input-validation failures raise `MissingRequiredArgumentError` or `InvalidArgumentError`, and a required step-up raises `MfaRequiredError`.

### Basic handling

```python
from auth0_server_python.error import Auth0Error

try:
    result = await server_client.signin_with_passkey(
        auth_session=auth_session,
        authn_response=authn_response,
        store_options={"request": request, "response": response},
    )
except Auth0Error as e:
    return {"error": str(e)}
```

### Advanced handling (when actions differ by case)

```python
from auth0_server_python.error import PasskeyError, MfaRequiredError, Auth0Error

try:
    result = await server_client.signin_with_passkey(
        auth_session=auth_session,
        authn_response=authn_response,
        store_options={"request": request, "response": response},
    )
except MfaRequiredError as e:
    return start_mfa(e.mfa_token)          # step-up required - challenge + verify via client.mfa,
                                           # then store the returned tokens (see "Completing MFA
                                           # on a passkey login" above)
except PasskeyError as e:
    if e.status_code == 429:
        return {"error": "rate_limited", "retry_after": e.retry_after}
    return {"error": e.code, "detail": e.message}   # branch on e.code or e.status_code, never on message text
except Auth0Error as e:
    return {"error": str(e)}
```

### Common error codes (`PasskeyErrorCode`)

- `passkey_challenge_error` - the signup/login challenge request failed
- `passkey_token_error` - token exchange failed (also used for a rejected DPoP downgrade)
- `invalid_response` - Auth0 returned a response that could not be parsed
- `invalid_grant` - a verification code was wrong, or the session is no longer valid. `is_verification_retryable` tells the two apart.
- `invalid_request` - Auth0 rejected the request as invalid, for example a missing verification code. On its own it does not mean the session can be resumed.

`PasskeyError` also exposes `status_code` (the HTTP status when Auth0 returned an error response, otherwise `None`), `retry_after` (seconds from the `Retry-After` header, or `None` when the header is absent or not a whole number of seconds), `auth_session`, `verification_required` and `is_verification_retryable` for [identifier verification](#4-identifier-verification-optional). A rate-limited challenge or token exchange has `status_code` 429, and its `code` depends on which Auth0 limit was hit. The per-IP limit on the challenge endpoints applies to public clients only. Treat `auth_session` on the error like any other session credential and keep it out of logs.

> [!NOTE]
> `auth_session` is a short-lived (typically about a minute, or 15 min when `verification_required` is set, matching the `timeout` in `authn_params_public_key`) credential. Never log or persist it. If the ceremony takes too long, re-request the challenge.
