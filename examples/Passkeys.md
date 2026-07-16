# Passkey Authentication

Passkeys let users sign up and log in with [WebAuthn](https://www.w3.org/TR/webauthn-2/) credentials (Touch ID, Face ID, Windows Hello, or a hardware security key) instead of a password. This guide covers the **primary authentication** flow on `ServerClient` — signing a user up or in with a passkey and establishing a server-side session.

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
- [Error Handling](#error-handling)

## How the flow works

A passkey ceremony is always **two steps**, because the WebAuthn signature happens in the browser between them:

1. **Challenge** — the SDK asks Auth0 for a challenge (`passkey_signup_challenge` / `passkey_login_challenge`). Auth0 returns an `auth_session` and the WebAuthn options (`authn_params_public_key`).
2. **Browser** — your front end passes those options to `navigator.credentials.create()` (signup) or `navigator.credentials.get()` (login). The authenticator produces a signed credential.
3. **Verify / sign-in** — the SDK exchanges the signed credential for tokens (`signin_with_passkey`) and **creates a server-side session**, exactly like every other login path.

## Prerequisites

```python
from auth0_server_python.auth_server.server_client import ServerClient

server_client = ServerClient(
    domain="YOUR_CUSTOM_DOMAIN",
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    secret="YOUR_SECRET",
)
```

The **Passkey** grant (`urn:okta:params:oauth:grant-type:webauthn`) must be enabled for your application under **Applications → Your App → Grant Types**.

## 1. Passkey Signup

### Step 1 — Request a signup challenge

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
```

> [!TIP]
> `PasskeyUserProfile` allows extra fields — any additional profile attribute your tenant accepts (for example `given_name`, `family_name`, `picture`) passes through without an SDK change. Pass tenant-specific custom data via the separate `user_metadata` argument.

### Step 2 — Create the credential in the browser

Pass `authn_params_public_key` to `navigator.credentials.create()`. The resulting credential serializes to the shape the SDK expects in step 3 (`id`, `rawId`, `type`, and a `response` object with `clientDataJSON` + `attestationObject`).

### Step 3 — Verify and establish the session

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
print(f"Signed up and logged in: {user['sub']}")
```

`signin_with_passkey` returns a `PasskeyLoginResult` whose `state_data` holds the user claims and token sets — the same shape as `complete_interactive_login` and `login_with_custom_token_exchange`. The session is persisted to your configured state store.

## 2. Passkey Login

Identical shape, different endpoints. The login challenge takes an optional `username` hint (for conditional UI), and the browser uses `navigator.credentials.get()`.

```python
# Step 1 — login challenge
challenge = await server_client.passkey_login_challenge(
    username="existing.user@example.com",            # optional
    connection="Username-Password-Authentication",   # optional
    store_options={"request": request, "response": response},
)

# Step 2 — browser: navigator.credentials.get(challenge.authn_params_public_key)

# Step 3 — sign in. The login credential's response carries
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
> The SDK is transparent to the signup-vs-login difference in the credential `response` — both flow through the same `PasskeyAuthResponse.response` dict. Send exactly the keys the browser produced.

## 3. DPoP-bound passkey tokens (optional)

Pass an optional `dpop_key` to bind the issued tokens to a key your server holds ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)), so a stolen token alone cannot be replayed. DPoP is **opt-in**: omit `dpop_key` and sign-in returns ordinary Bearer tokens with no behaviour change.

```python
from jwcrypto import jwk

dpop_key = jwk.JWK.generate(kty="EC", crv="P-256")  # you generate and keep this key (Tier 0)

result = await server_client.signin_with_passkey(
    auth_session=challenge.auth_session,
    authn_response=authn_response,
    dpop_key=dpop_key,
    store_options={"request": request, "response": response},
)
```

When `dpop_key` is supplied, the SDK attaches a token-endpoint proof so Auth0 issues a DPoP-bound token, transparently handles the server-nonce challenge, and **rejects a Bearer downgrade** — if the server returns an unbound token, `signin_with_passkey` raises `PasskeyError` rather than silently accepting a token bound to a key it never used.

> [!TIP]
> Reuse the **same** `dpop_key` for any subsequent My Account API calls made with the resulting token — the token is bound to that one key. See [MyAccountAuthenticationMethods.md → DPoP](MyAccountAuthenticationMethods.md#dpop).

> [!WARNING]
> The `dpop_key` private key is a **Tier 0 secret**. Keep it in your secret store (KMS/HSM), never log it (`repr()` is redacted, but `key.export_private()` is not), use **one key per user/session** (never share across principals), and use **EC P-256 only** — any other key type fails closed with a `ValueError` before any network call.

## Error Handling

The three passkey methods raise `PasskeyError` (a subclass of `Auth0Error`). Input-validation failures raise `MissingRequiredArgumentError`; a required step-up raises `MfaRequiredError`. For most code, catching `Auth0Error` is enough.

### Basic handling (recommended)

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
    return start_mfa(e.mfa_token)          # step-up required — continue with MfaClient
except PasskeyError as e:
    return {"error": e.code, "detail": e.message}   # branch on e.code, never on message text
except Auth0Error as e:
    return {"error": str(e)}
```

### Common error codes (`PasskeyErrorCode`)

- `passkey_challenge_error` — the signup/login challenge request failed
- `passkey_token_error` — token exchange failed (also used for a rejected DPoP downgrade)
- `invalid_response` — Auth0 returned a response that could not be parsed

> [!NOTE]
> `auth_session` is a short-lived (typically ~5 min) Tier 1 credential. It is redacted in the SDK's model `repr()`, and you should never log or persist it. If the ceremony takes too long, re-request the challenge.
