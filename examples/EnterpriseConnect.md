# Enterprise Connect (Embedded Login)

Enterprise Connect lets your application sign users in through their company's identity provider while **your app owns the session**. Auth0 acts as a pure SSO relay: it authenticates the user and returns verified claims, but issues no refresh token and holds no session on your behalf. This guide covers the `enterprise_connect` mode on `ServerClient`, email-domain discovery, the callback contract, and federated logout.

> [!IMPORTANT]
> Enterprise Connect is an Early Access feature. Tenant setup (entitlements, connection type, and the exact claims a token carries) depends on your Auth0 configuration and may change. Treat the tenant-side steps below as a starting point and confirm them against your tenant. The SDK behavior described here is stable.

> [!IMPORTANT]
> These flows are for confidential server-side applications. The verified claims and access token are handed to your server, which creates and owns the user session. The browser should only ever receive your application's own session cookie or opaque session reference, never an Auth0 token.

## Table of Contents

- [How the flow works](#how-the-flow-works)
- [Prerequisites](#prerequisites)
- [1. Configure the client](#1-configure-the-client)
- [2. Discover and start the login](#2-discover-and-start-the-login)
- [3. Complete the callback](#3-complete-the-callback)
- [4. Organizations and multi-tenant apps](#4-organizations-and-multi-tenant-apps)
- [5. Logout](#5-logout)
- [What is not available in Enterprise Connect](#what-is-not-available-in-enterprise-connect)
- [Error Handling](#error-handling)

## How the flow works

1. The user enters their email. Your app calls `start_enterprise_login()`, which runs [WebFinger](https://datatracker.ietf.org/doc/html/rfc7033) discovery on the email domain.
2. If the domain is managed by Auth0 for enterprise SSO, the SDK returns an authorization URL with the email as `login_hint` so Auth0 can resolve the connection and organization. If it is not managed, the method returns `None` and your app falls back to its own login.
3. The user authenticates at their identity provider and is redirected back to your callback.
4. Your app calls `complete_interactive_login()`. The SDK exchanges the code, verifies the ID token's signature and issuer, and returns the claims from it. It persists **nothing** and issues no refresh token.
5. Your app creates its own first-party session from the returned claims.

The contract is inverted from a normal login: the SDK does not store a session, so the session-reading methods (`get_session`, `get_access_token`) are not available in this mode.

## Prerequisites

Enterprise Connect requires a **Regular Web Application** with a client secret. The tenant and connection must be provisioned for Enterprise Connect (Early Access), and WebFinger discovery must be enabled on the tenant. Work with your Auth0 contact to confirm entitlements for your tenant.

Do not request `offline_access` and do not set a static `organization` on the client. Enterprise Connect issues no refresh token, and the organization is resolved from the login email at Auth0. The SDK warns at construction if either is set.

## 1. Configure the client

Opt in with `enterprise_connect=True`. Supply a `transaction_store` (used to protect the callback with `state` and PKCE); a `state_store` is not needed, because the SDK persists no session.

```python
from auth0_server_python.auth_server.server_client import ServerClient

server_client = ServerClient(
    domain="YOUR_AUTH0_DOMAIN",
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    secret="YOUR_SECRET",
    redirect_uri="https://app.example.com/auth/callback",
    authorization_params={"scope": "openid profile email"},
    enterprise_connect=True,
)
```

For apps using request/response-backed stores or multiple custom domains, pass `store_options={"request": request, "response": response}` to each method that reads or writes transaction state.

## 2. Discover and start the login

`start_enterprise_login()` takes the user's email, runs discovery, and returns the authorization URL when the domain is managed, or `None` when it is not.

```python
from auth0_server_python.auth_types import StartEnterpriseLoginOptions

auth_url = await server_client.start_enterprise_login(
    StartEnterpriseLoginOptions(
        email=user_email,
        app_state={"return_to": "/dashboard"},
    ),
    store_options={"request": request, "response": response},
)

if auth_url:
    return redirect(auth_url)          # enterprise SSO
return redirect("/login/password")     # your own non-enterprise login
```

> [!IMPORTANT]
> Discovery is a routing hint, not an authorization decision. It fails closed to "not managed" on any error, so a discovery failure routes the user to your fallback login rather than granting access. It never, on its own, signs anyone in - the callback must still complete.

If you only need the discovery signal (for example, to decide which login button to show), call the standalone helper. It takes no client instance and is stateless.

```python
from auth0_server_python.auth_server import is_federated_domain

managed = await is_federated_domain("YOUR_AUTH0_DOMAIN", "acme.example")
```

## 3. Complete the callback

When Auth0 redirects back, call `complete_interactive_login()`. In Enterprise Connect mode it returns the verified claims and an access token instead of a session record.

```python
result = await server_client.complete_interactive_login(
    str(request.url),
    store_options={"request": request, "response": response},
)

user = result["user"]            # verified UserClaims (includes sub, email, and org_id when present)
access_token = result["token_set"]["access_token"]
id_token = result["id_token"]
domain = result["domain"]

# Create YOUR OWN session from these claims.
create_app_session(user_id=user.sub)

# app_state round-trips whatever you passed at start_enterprise_login.
app_state = result.get("app_state") or {}
return redirect(app_state.get("return_to", "/"))
```

The returned dict contains:

- `user` - the verified `UserClaims`, parsed from the ID token that Enterprise Connect returns
- `token_set` - `audience`, `access_token`, `scope`, and `expires_at`
- `id_token` - the raw ID token, for your own use
- `domain` - the Auth0 domain the login came from
- `app_state` - present only when you passed `app_state` at `start_enterprise_login()`

`result` is a plain dict, so index it with `result["user"]`. `user` is a `UserClaims` model with no dict access, so read claims by attribute like `user.org_id`.

The SDK verifies the ID token's signature and issuer, and derives the returned claims from it, before returning. It does not write a session store record and retains no refresh token.

## 4. Organizations and multi-tenant apps

Auth0 stamps the resolved organization into the token as `org_id`, available on `result["user"]`. The SDK surfaces it but does not enforce it. It cannot know which organization *your* app expected for this user.

> [!WARNING]
> Validate `org_id` after every callback, regardless of routing. WebFinger discovery and `login_hint` are routing mechanisms, not security controls. On their own they do not prove the user belongs to a customer you serve. Read `org_id` from the returned claims and check it against your own record of known organizations before creating the session. Without this check, a user who authenticates through any managed connection could obtain a session in a context you did not intend. This is an authorization decision your app owns.

```python
user = result["user"]
if user.org_id not in allowed_orgs_for(current_customer):
    raise Forbidden("user does not belong to this organization")
```

If you serve exactly one organization, this is a single check against your one known org, not a reason to skip it. An app that skips it today can silently let users in from other tenants the day it onboards a second customer.

## 5. Logout

Clear your own application session first, then send the user to the Auth0 logout URL.

```python
from auth0_server_python.auth_types import LogoutOptions

destroy_app_session()

logout_url = await server_client.logout(
    LogoutOptions(return_to="https://app.example.com/login"),
    store_options={"request": request, "response": response},
)
return redirect(logout_url)
```

By default this ends the Auth0 session but leaves the upstream identity provider session intact, so the user is not re-prompted at their IdP on the next login. To also terminate the IdP session, pass `federated=True`.

```python
logout_url = await server_client.logout(
    LogoutOptions(return_to="https://app.example.com/login", federated=True),
)
```

> [!NOTE]
> `return_to` must be an absolute URL on your tenant's Allowed Logout URLs list. Auth0 rejects a URL that is not allow-listed.

## What is not available in Enterprise Connect

Auth0 issues no refresh token and the SDK stores no session in this mode. Any member that reads a session or refreshes a token raises `EnterpriseConnectError`. Catch it and branch on `code`.

| Member | Behavior |
|---|---|
| `get_session()` | Raises, code `enterprise_connect_session_unavailable` |
| `get_access_token()` | Raises, code `enterprise_connect_access_token_unavailable`. Read the token from `complete_interactive_login()` instead |
| Refresh, user linking, connected accounts, session transfer, passkey sign-in, `login_with_custom_token_exchange`, and the `mfa` and `passwordless` sub-clients | Raise, code `enterprise_connect_method_unavailable` |
| `handle_backchannel_logout()` | No-op. The SDK holds no session to revoke |
| `custom_token_exchange()` | Works once, while the callback access token is valid. No refresh after it expires |

Own the session and any token refresh in your app.

## Error Handling

```python
from auth0_server_python.error import ApiError, EnterpriseConnectError

# The callback can fail on the token exchange or on unverifiable claims.
try:
    result = await server_client.complete_interactive_login(
        str(request.url),
        store_options={"request": request, "response": response},
    )
except ApiError as e:
    return {"error": e.code}

# Session and token methods are unavailable in this mode and raise EnterpriseConnectError.
try:
    await server_client.get_access_token()
except EnterpriseConnectError as e:
    return {"error": e.code}
```

Errors you may see:

- `EnterpriseConnectError` - a session or token method is unavailable in this mode. Branch on `code`:
  - `enterprise_connect_session_unavailable` - `get_session()` was called
  - `enterprise_connect_access_token_unavailable` - `get_access_token()` was called
  - `enterprise_connect_method_unavailable` - any other session or refresh dependent member was called
- `MissingRequiredArgumentError` - `start_enterprise_login()` was called without an email
- `InvalidArgumentError` - the email is not a valid address
- `ApiError` - the token exchange failed, or the login returned no verifiable claims (`invalid_response`)
