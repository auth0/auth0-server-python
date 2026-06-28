# My Account API — Authentication Methods & Factors

The [My Account API](https://auth0.com/docs/manage-users/my-account-api) lets a **logged-in user manage their own account**. This guide covers the **authentication-methods** and **factors** surface: enrolling a new passkey (or other factor), and listing, reading, renaming, and deleting a user's enrolled methods.

> [!NOTE]
> This is a different My Account resource from [Connected Accounts](ConnectedAccounts.md) (Token Vault). Connected-accounts management is exposed as convenience methods on `ServerClient`; **authentication-method management is on `MyAccountClient` directly**, because each call takes a user access token you obtain yourself. The two share the same My Account setup (activation, MRRT, scopes, `MyAccountApiError`) — see [ConnectedAccounts.md → Pre-requisites](ConnectedAccounts.md#pre-requisites) for that common setup.

> [!NOTE]
> To **sign in** with a passkey (rather than manage one), see [examples/Passkeys.md](Passkeys.md). To **bind these calls to a held key** with DPoP, see [examples/DPoP.md](DPoP.md).

## Table of Contents

- [Prerequisites](#prerequisites)
- [Obtaining a scoped token](#obtaining-a-scoped-token)
- [1. List factors available for enrollment](#1-list-factors-available-for-enrollment)
- [2. Enroll an authentication method (passkey)](#2-enroll-an-authentication-method-passkey)
- [3. List authentication methods](#3-list-authentication-methods)
- [4. Get a single authentication method](#4-get-a-single-authentication-method)
- [5. Update (rename) an authentication method](#5-update-rename-an-authentication-method)
- [6. Delete an authentication method](#6-delete-an-authentication-method)
- [DPoP](#dpop)
- [Error Handling](#error-handling)
- [Additional Resources](#additional-resources)

## Prerequisites

1. [Activate the My Account API](https://auth0.com/docs/manage-users/my-account-api#activate-the-my-account-api) on your tenant and enable access for your application.
2. [Configure MRRT](https://auth0.com/docs/secure/tokens/refresh-tokens/multi-resource-refresh-token) so your refresh-token policy can mint tokens for the My Account audience (`https://{yourDomain}/me/`) with the authentication-methods scopes.
3. Passkey enrollment additionally requires a [Custom Domain](https://auth0.com/docs/customize/custom-domains) and the native passkey feature on your tenant.

The scopes for this surface (note the **hyphens**):

| Operation | Scope |
|-----------|-------|
| List factors | `read:me:factors` |
| List / get methods | `read:me:authentication-methods` |
| Enroll / verify | `create:me:authentication-methods` |
| Update | `update:me:authentication-methods` |
| Delete | `delete:me:authentication-methods` |

> [!TIP]
> As with Connected Accounts, set the default `scope` for the My Account audience when constructing `ServerClient` to avoid a fresh token request per scope. See [ConnectedAccounts.md → A note about scopes](ConnectedAccounts.md#a-note-about-scopes).

## Obtaining a scoped token

`MyAccountClient` is **stateless** — it takes a correctly-scoped user access token on every call. Obtain that token from your `ServerClient` session via MRRT, then construct the client:

```python
from auth0_server_python.auth_server.my_account_client import MyAccountClient

# Fresh My Account-scoped token for the current session (MRRT exchange)
access_token = await server_client.get_access_token(
    store_options={"request": request, "response": response},
    audience=f"https://{YOUR_CUSTOM_DOMAIN}/me/",
    scope="create:me:authentication-methods read:me:authentication-methods read:me:factors",
)

my_account = MyAccountClient(domain=YOUR_CUSTOM_DOMAIN)
```

## 1. List factors available for enrollment

```python
factors = await my_account.get_factors(access_token=access_token)
for factor in factors.factors:
    print(factor.type, factor.usage)
```

## 2. Enroll an authentication method (passkey)

Enrollment is a **two-step** ceremony, mirroring sign-in: request a challenge, sign it in the browser, then verify.

### Step 1 — Start enrollment

```python
from auth0_server_python.auth_types import EnrollAuthenticationMethodRequest

challenge = await my_account.enroll_authentication_method(
    access_token=access_token,
    request=EnrollAuthenticationMethodRequest(type="passkey"),
)

# challenge.authentication_method_id  -> id of the new (unverified) method
# challenge.auth_session              -> Tier 1 session credential (do not log)
# challenge.authn_params_public_key   -> pass to navigator.credentials.create()
```

`EnrollAuthenticationMethodRequest.type` is a closed set: `passkey`, `email`, `phone`, `totp`, `push-notification`, `recovery-code`, `password`. For non-passkey types, supply the relevant fields (`email`, `phone_number`, `preferred_authentication_method`). An invalid type fails at construction with a clear `ValidationError`.

### Step 2 — Create the credential in the browser

Pass `challenge.authn_params_public_key` to `navigator.credentials.create()` and collect the resulting credential.

### Step 3 — Verify enrollment

```python
from auth0_server_python.auth_types import (
    VerifyAuthenticationMethodRequest,
    PasskeyAuthResponse,
)

method = await my_account.verify_authentication_method(
    access_token=access_token,
    authentication_method_id=challenge.authentication_method_id,
    request=VerifyAuthenticationMethodRequest(
        auth_session=challenge.auth_session,
        authn_response=PasskeyAuthResponse(
            id=credential["id"],
            raw_id=credential["rawId"],
            type="public-key",
            response={
                "clientDataJSON": credential["response"]["clientDataJSON"],
                "attestationObject": credential["response"]["attestationObject"],
            },
        ),
    ),
)
print(f"Enrolled: {method.id} ({method.type})")
```

> [!NOTE]
> For non-passkey types, set the matching field on `VerifyAuthenticationMethodRequest` instead of `authn_response`: `otp_code` (email/phone/totp), `recovery_code`, or `password`. A push enrollment needs only `auth_session`.

## 3. List authentication methods

```python
all_methods = await my_account.list_authentication_methods(access_token=access_token)

# Filter by type
passkeys = await my_account.list_authentication_methods(
    access_token=access_token,
    type_filter="passkey",
)
for m in passkeys.authentication_methods:
    print(m.id, m.type, m.created_at)
```

> [!NOTE]
> `AuthenticationMethod` and `Factor` are forward-tolerant (`extra="allow"`): fields or method/factor types Auth0 adds later still deserialize. Don't switch exhaustively on `type` — handle unknown types gracefully.

## 4. Get a single authentication method

```python
method = await my_account.get_authentication_method(
    access_token=access_token,
    authentication_method_id="passkey|abc123",
)
```

> [!NOTE]
> Method IDs (e.g. `passkey|abc123`) can contain characters like `|`. The SDK URL-encodes every ID it places in a path, so pass the raw ID exactly as returned — do not pre-encode it.

## 5. Update (rename) an authentication method

```python
from auth0_server_python.auth_types import UpdateAuthenticationMethodRequest

method = await my_account.update_authentication_method(
    access_token=access_token,
    authentication_method_id="passkey|abc123",
    request=UpdateAuthenticationMethodRequest(name="My Work Laptop"),
)
```

## 6. Delete an authentication method

```python
await my_account.delete_authentication_method(
    access_token=access_token,
    authentication_method_id="passkey|abc123",
)
# Returns None on success (HTTP 204).
```

## DPoP

Every method above accepts an optional `dpop_key` to present a sender-constrained token (`Authorization: DPoP` + a per-request proof) instead of a Bearer token. Pass the **same key** the access token was bound to:

```python
methods = await my_account.list_authentication_methods(
    access_token=access_token,
    dpop_key=dpop_key,
)
```

See [examples/DPoP.md](DPoP.md) for key generation, the `dpop_key` vs `dpop_proof` distinction, and nonce handling.

## Error Handling

All errors inherit from `Auth0Error`. My Account API errors are `MyAccountApiError` (RFC 7807 problem-details, carrying `status`, `detail`, and optional `validation_errors`); missing arguments raise `MissingRequiredArgumentError`; transport or non-JSON responses surface as `ApiError`.

### Basic handling (recommended)

```python
from auth0_server_python.error import Auth0Error

try:
    methods = await my_account.list_authentication_methods(access_token=access_token)
except Auth0Error as e:
    return {"error": str(e)}
```

### Advanced handling (when actions differ by case)

```python
from auth0_server_python.error import Auth0Error, MyAccountApiError

try:
    await my_account.enroll_authentication_method(
        access_token=access_token,
        request=EnrollAuthenticationMethodRequest(type="passkey"),
    )
except MyAccountApiError as e:
    if e.status == 401:
        return redirect_to_login()                       # token expired
    if e.status == 403:
        return {"error": "Missing required scope"}       # e.g. create:me:authentication-methods
    if e.status == 400 and e.validation_errors:
        return {"error": "Validation failed", "details": e.validation_errors}
    raise
except Auth0Error as e:
    return {"error": str(e)}
```

> [!NOTE]
> Enrollment raises `MyAccountApiError`/`ApiError`, whereas passkey **sign-in** (`ServerClient`) raises `PasskeyError`. They are two distinct API surfaces — an auth grant versus a My Account resource — so write the `except` that matches the call you made.

### Common error types

- **`Auth0Error`** (base): catch for general handling
- **`MyAccountApiError`**: My Account API errors with `status`, `detail`, optional `validation_errors`
- **`MissingRequiredArgumentError`**: a required parameter (`access_token`, `authentication_method_id`, `request`) was not provided
- **`ApiError`**: transport failure or a non-JSON error body

## Additional Resources

- [Connected Accounts (Token Vault)](ConnectedAccounts.md) — the other My Account surface, and shared My Account/MRRT setup
- [Passkey Authentication](Passkeys.md) — signing in with a passkey
- [DPoP](DPoP.md) — sender-constrained tokens
- [Auth0 My Account API documentation](https://auth0.com/docs/manage-users/my-account-api)
