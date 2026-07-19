# Passkey Authentication

Passkeys let users sign up and log in with [WebAuthn](https://www.w3.org/TR/webauthn-2/) credentials (Touch ID, Face ID, Windows Hello, or a hardware security key) instead of a password. This guide covers the **primary authentication** flow on `ServerClient` — signing a user up or in with a passkey and establishing a server-side session.

> [!NOTE]
> Passkeys require a [Custom Domain](https://auth0.com/docs/customize/custom-domains) (WebAuthn binds the credential to the relying-party domain) and the native passkey feature enabled on your tenant. See the [Auth0 passkey documentation](https://auth0.com/docs/authenticate/database-connections/passkeys).

## Table of Contents

- [How the flow works](#how-the-flow-works)
- [Prerequisites](#prerequisites)
- [1. Passkey Signup](#1-passkey-signup)
- [2. Passkey Login](#2-passkey-login)
  - [Completing MFA on a passkey login (and where the session comes from)](#completing-mfa-on-a-passkey-login-and-where-the-session-comes-from)
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

### Completing MFA on a passkey login (and where the session comes from)

When a passkey login needs a second factor, `signin_with_passkey` raises `MfaRequiredError` **before** it creates a session. You finish the login by challenging and verifying through `client.mfa`, then **store the returned tokens yourself** — on this path the SDK does not persist the session for you (`persist` defaults to `False`, and there is no existing session to update yet):

```python
from auth0_server_python.error import MfaRequiredError

try:
    result = await server_client.signin_with_passkey(
        auth_session=auth_session,
        authn_response=authn_response,
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

    # 2. Verify the user's code. persist=False (the default) → the SDK
    #    returns the tokens instead of writing a session.
    verify_response = await server_client.mfa.verify(
        {"mfa_token": e.mfa_token, "otp": otp_code},
        store_options={"request": request, "response": response},
    )

    # 3. Persist the tokens into YOUR session yourself — this is the step the
    #    SDK skips on the MFA path because no session existed at login time.
    save_session_for_user(
        access_token=verify_response.access_token,
        id_token=verify_response.id_token,
        refresh_token=verify_response.refresh_token,
    )
```

> [!NOTE]
> Do **not** pass `persist=True` on this path. It updates an *existing* session, and a passkey-first login has none yet, so it raises `MfaVerifyError("No existing session found…")` — discarding the tokens `verify` just obtained. Use `persist=False` and store the returned tokens as shown above. (This is pre-existing MFA-client behavior, unrelated to passkeys.)

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
    return start_mfa(e.mfa_token)          # step-up required — challenge + verify via client.mfa,
                                           # then store the returned tokens (see "Completing MFA
                                           # on a passkey login" above)
except PasskeyError as e:
    return {"error": e.code, "detail": e.message}   # branch on e.code, never on message text
except Auth0Error as e:
    return {"error": str(e)}
```

### Common error codes (`PasskeyErrorCode`)

- `passkey_challenge_error` — the signup/login challenge request failed
- `passkey_token_error` — token exchange failed
- `invalid_response` — Auth0 returned a response that could not be parsed

> [!NOTE]
> `auth_session` is a short-lived (typically ~5 min) Tier 1 credential. It is redacted in the SDK's model `repr()`, and you should never log or persist it. If the ceremony takes too long, re-request the challenge.
