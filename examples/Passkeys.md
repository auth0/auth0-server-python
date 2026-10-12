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

Enable identifier verification for email, phone, or both on your database connection. Passkeys must be enabled on that connection, and a custom domain must be configured.

### The flow

1. Request the challenge. If `verification_required` is set, collect a code for each identifier it lists.
2. Collect the codes before creating the credential, so a failed verification does not leave a saved passkey for an unfinished signup.
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

The keys of `verification` must be `email` or `phone`, as listed in `verification_required`. Any other key raises `InvalidArgumentError`, and blank codes are ignored. Omit `verification` when `verification_required` is `None`.

When verification is required, the session and the `timeout` in `authn_params_public_key` last 15 minutes.

### Handling a wrong code

After a wrong code the session stays valid. `signin_with_passkey` raises a `PasskeyError` with `is_verification_retryable` set to `True`, and its `verification_required` lists the identifiers still unverified. Resubmit codes for those identifiers only.

```python
from auth0_server_python.error import PasskeyError

MAX_ATTEMPTS = 3
auth_session = challenge.auth_session
codes = {"email": email_code, "phone": phone_code}

for attempt in range(MAX_ATTEMPTS):
    try:
        result = await server_client.signin_with_passkey(
            auth_session=auth_session,
            authn_response=authn_response,
            verification=codes,
            store_options={"request": request, "response": response},
        )
        break
    except PasskeyError as e:
        if not e.is_verification_retryable or attempt == MAX_ATTEMPTS - 1:
            raise
        auth_session = e.auth_session
        codes = ask_user_for_codes(e.verification_required)
```

Retry with the `auth_session` from the error and the same `authn_response`. Cap the number of attempts, because Auth0 also limits them.

`is_verification_retryable` is `False` in these cases.

- Too many wrong codes, an expired code, or an expired session. Start again from the signup challenge.
- A missing code raises `invalid_request` and the session stays valid. Resubmit with the same `auth_session` and every required code.
- A server error (`server_error`) may or may not have ended the session. Retry with the same `auth_session`, `authn_response` and codes. If the call fails with `invalid_grant` and no `auth_session`, start again from the signup challenge.
- Any other failure is raised with the code Auth0 returned.

If the connection drops after Auth0 accepts the final code, the session has ended because each code works once. Start again from the signup challenge.

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
    return {"error": e.code, "detail": e.message}   # branch on e.code, never on message text
except Auth0Error as e:
    return {"error": str(e)}
```

### Common error codes (`PasskeyErrorCode`)

- `passkey_challenge_error` - the signup/login challenge request failed
- `passkey_token_error` - token exchange failed (also used for a rejected DPoP downgrade)
- `invalid_response` - Auth0 returned a response that could not be parsed
- `too_many_requests` when a challenge or the token exchange is rate limited

`PasskeyError` also exposes `auth_session`, `verification_required` and `is_verification_retryable` for [identifier verification](#4-identifier-verification-optional). Rate limiting on a challenge or the token exchange raises code `too_many_requests`. The per-IP limit on the challenge endpoints applies to public clients only. Treat `auth_session` on the error like any other session credential and keep it out of logs.

> [!NOTE]
> `auth_session` is a short-lived (typically about a minute, or 15 min when `verification_required` is set) credential. Never log or persist it. If the ceremony takes too long, re-request the challenge.
