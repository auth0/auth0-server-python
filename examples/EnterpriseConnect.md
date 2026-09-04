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
- [4. Protect your routes](#4-protect-your-routes)
- [5. Organizations and multi-tenant apps](#5-organizations-and-multi-tenant-apps)
- [6. Logout](#6-logout)
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

> [!IMPORTANT]
> The SDK writes its transaction cookie onto the `response` you pass in `store_options`: the `state` and PKCE values when a login starts, and a deletion of that cookie when the callback completes. Return that same `response` object, with your own redirect and session cookie set on it. Do not return a fresh `redirect(url)` built after the SDK call. A new response object carries none of the SDK's `Set-Cookie` headers, so the transaction cookie never reaches the browser and the callback finds no transaction to match. The examples below create the response first, thread it through `store_options`, then set its `Location` last. The pattern is framework-neutral: `redirect(...)`, `.set_cookie(...)`, and `.headers["Location"]` map onto the equivalent calls in your web framework.

## 2. Discover and start the login

Your app must serve a login page that collects the user's work email. Pass it to `start_enterprise_login()`, which runs WebFinger discovery and returns the authorization URL when the domain is managed, or `None` when it is not.

```python
from auth0_server_python.auth_types import StartEnterpriseLoginOptions
from auth0_server_python.error import MissingRequiredArgumentError, InvalidArgumentError

response = redirect("/")  # placeholder target, overwritten once discovery returns

try:
    auth_url = await server_client.start_enterprise_login(
        StartEnterpriseLoginOptions(
            email=user_email,
            app_state={"return_to": "/dashboard"},
        ),
        store_options={"request": request, "response": response},
    )
except (MissingRequiredArgumentError, InvalidArgumentError):
    auth_url = None

response.headers["Location"] = auth_url or "/login/password"
return response
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
response = redirect("/")  # placeholder target, overwritten once app_state is known

result = await server_client.complete_interactive_login(
    str(request.url),
    store_options={"request": request, "response": response},
)

user = result["user"]
access_token = result["token_set"]["access_token"]
id_token = result["id_token"]
domain = result["domain"]

response.set_cookie(
    "app_session",
    sign_session({"sub": user.get("sub"), "email": user.get("email"), "org_id": user.get("org_id") or ""}),
    httponly=True,
    secure=True,
    samesite="lax",
)

app_state = result.get("app_state") or {}
response.headers["Location"] = app_state.get("return_to", "/")
return response
```

The returned dict contains:

- `user` - the verified claims from the ID token, as a dict
- `token_set` - `audience`, `access_token`, `scope`, and `expires_at`
- `id_token` - the raw ID token, for your own use
- `domain` - the Auth0 domain the login came from
- `app_state` - present only when you passed `app_state` at `start_enterprise_login()`

`result` and `user` are both plain dicts. Read claims with `user.get("sub")` so a claim the connection did not return yields `None` instead of raising `KeyError`. `sub` is always present, the optional claims (`email`, `org_id`, `name`) may not be.

The SDK verifies the ID token's signature and issuer, and derives the returned claims from it, before returning. It does not write a session store record and retains no refresh token.

### Sign the session cookie

The session cookie is your trust boundary now, not Auth0's. A signed-in user controls their own cookies, so an unsigned session lets them rewrite `sub`, `email`, or `org_id` to impersonate another user or forge membership in an organization they were denied. Sign the cookie with a server-side secret and verify the signature in constant time before trusting any claim in it.

```python
import base64
import hashlib
import hmac
import json
from typing import Optional

_SESSION_SECRET = b"YOUR_SESSION_SECRET"

def sign_session(claims: dict) -> str:
    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    sig = hmac.new(_SESSION_SECRET, body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"

def read_session(cookie: Optional[str]) -> Optional[dict]:
    if not cookie or "." not in cookie:
        return None
    body, _, sig = cookie.partition(".")
    expected = hmac.new(_SESSION_SECRET, body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    padded = body + "=" * (-len(body) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(padded).decode())
    except ValueError:
        return None
```

> [!IMPORTANT]
> Hold `_SESSION_SECRET` server-side only (Tier 0) and never ship it to the browser. Use a dedicated secret rather than reusing one for another purpose. The `hmac.compare_digest` check is what makes a forged cookie fail closed - a plain `==` comparison leaks the signature through timing.

## 4. Protect your routes

Your app owns the session - the SDK holds nothing. Check your session store at the start of any route that requires authentication and redirect to your login page when the session is absent.

```python
session = read_session(request.cookies.get("app_session"))
if not session:
    return redirect("/login")

your_template.render(user=session)
```

> [!IMPORTANT]
> Do not store an Auth0 access or ID token in your session. Store only the claims you need (for example `sub`, `email`, `org_id`). The browser must never see an Auth0 token.

## 5. Organizations and multi-tenant apps

Auth0 stamps the resolved organization into the token as `org_id`, available on `result["user"]`. The SDK surfaces it but does not enforce it. It cannot know which organization *your* app expected for this user.

> [!WARNING]
> Validate `org_id` after every callback, regardless of routing. WebFinger discovery and `login_hint` are routing mechanisms, not security controls. On their own they do not prove the user belongs to a customer you serve. Read `org_id` from the returned claims and check it against your own record of known organizations before creating the session. Without this check, a user who authenticates through any managed connection could obtain a session in a context you did not intend. This is an authorization decision your app owns.

```python
user = result["user"]
if user.get("org_id") not in allowed_orgs_for(current_customer):
    raise Forbidden("user does not belong to this organization")
```

If you serve exactly one organization, this is a single check against your one known org, not a reason to skip it. An app that skips it today can silently let users in from other tenants the day it onboards a second customer.

## 6. Logout

Clear your own application session first, then send the user to the Auth0 logout URL.

```python
from auth0_server_python.auth_types import LogoutOptions

response = redirect("/")  # placeholder target, overwritten once logout returns
clear_app_session(response)  # delete your session cookie on the response you return

logout_url = await server_client.logout(
    LogoutOptions(return_to="https://app.example.com/login"),
    store_options={"request": request, "response": response},
)

response.headers["Location"] = logout_url
return response
```

By default this ends the Auth0 session but leaves the upstream identity provider session intact, so the user is not re-prompted at their IdP on the next login. To also terminate the IdP session, pass `federated=True`.

Federated logout ends the corporate IdP session itself, which can also sign the user out of other applications that share that same enterprise SSO, not just yours. Weigh that against the shared-device benefit before enabling it by default.

```python
logout_url = await server_client.logout(
    LogoutOptions(return_to="https://app.example.com/login", federated=True),
)
```

> [!NOTE]
> `return_to` must be an absolute URL on your tenant's Allowed Logout URLs list. Auth0 rejects a URL that is not allow-listed.

## What is not available in Enterprise Connect

These members work in Enterprise Connect mode:

| Member | Notes |
|---|---|
| `start_enterprise_login()` | EC login entry point |
| `start_interactive_login()` | Writes the transaction store only |
| `complete_interactive_login()` | Returns verified claims without persisting a session |
| `logout()` | Clears transaction state and returns the Auth0 logout URL |
| `custom_token_exchange()` | Works once, while the callback access token is valid. No refresh after it expires |
| `handle_backchannel_logout()` | No-op. The SDK holds no session to revoke |

Everything else raises `EnterpriseConnectError` with `code` `enterprise_connect_not_supported`. The message names the member that was called. For a session or access token, read them from `complete_interactive_login()` instead.

Own the session and any token refresh in your app.

## Error Handling

```python
from auth0_server_python.error import ApiError, EnterpriseConnectError

try:
    result = await server_client.complete_interactive_login(
        str(request.url),
        store_options={"request": request, "response": response},
    )
except ApiError as e:
    return {"error": e.code}

try:
    await server_client.get_access_token()
except EnterpriseConnectError as e:
    return {"error": e.code}
```

Errors you may see:

- `EnterpriseConnectError` - a session or refresh-dependent member is not available in this mode. Its `code` is always `enterprise_connect_not_supported`; the message names the member that was called
- `ApiError` - the token exchange failed, or the login returned no verifiable claims (`invalid_response`)
