# Organizations

[Organizations](https://auth0.com/docs/organizations) is a set of features that provide better support for developers building SaaS and B2B applications. This guide covers org login, invitation flows, error handling, and reading org data from the session.

- [1. Configuring the organization](#1-configuring-the-organization)
- [2. Log in using an organization name](#2-log-in-using-an-organization-name)
- [3. Accept user invitations](#3-accept-user-invitations)
- [4. Handling organization errors](#4-handling-organization-errors)
- [5. Reading organization data from the session](#5-reading-organization-data-from-the-session)

## 1. Configuring the organization

The `organization` parameter can be set at client initialization (dedicated-org) or per login (multi-org).

**Dedicated-org:** when a single instance of your application serves one organization, set `organization` at client initialization. Every login from that instance will enforce the org automatically.

```python
from auth0_server_python.auth_server.server_client import ServerClient

auth0 = ServerClient(
    domain="YOUR_AUTH0_DOMAIN",
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    secret="YOUR_SECRET",
    organization="org_abc123",
    authorization_params={
        "redirect_uri": "http://localhost:3000/auth/callback",
    }
)
```

```python
from fastapi import FastAPI, Request, Response
from starlette.responses import RedirectResponse

app = FastAPI()

@app.get("/auth/login")
async def login(request: Request, response: Response):
    authorization_url = await auth0.start_interactive_login(
        store_options={"request": request, "response": response}
    )
    return RedirectResponse(url=authorization_url)

@app.get("/auth/callback")
async def callback(request: Request, response: Response):
    result = await auth0.complete_interactive_login(
        str(request.url),
        store_options={"request": request, "response": response}
    )
    return RedirectResponse(url="/dashboard")
```

**Multi-org:** when one application instance serves multiple organizations, pass `organization` at login time using `StartInteractiveLoginOptions`. This overrides any client-level default for that specific login.

```python
from auth0_server_python.auth_types import StartInteractiveLoginOptions

@app.get("/auth/login")
async def login(request: Request, response: Response, org_id: str):
    authorization_url = await auth0.start_interactive_login(
        StartInteractiveLoginOptions(organization=org_id),
        store_options={"request": request, "response": response}
    )
    return RedirectResponse(url=authorization_url)
```

> [!NOTE]
> You do not need to pass `organization` to `complete_interactive_login`. The SDK stores it in the encrypted transaction at login time and reads it back at callback — the validation is automatic.

> [!IMPORTANT]
> In the multi-org pattern, validate that `org_id` comes from a trusted source (your own data, a verified session, or a registered tenant list) — never pass it unvalidated from a query parameter directly from an untrusted user.

## 2. Log in using an organization name

`organization` accepts either an org ID (starts with `org_`) or an org name (any other value). The SDK uses the prefix to determine which token claim to validate at callback:

- **`org_` prefix** → validates `org_id` claim (exact, case-sensitive match)
- **No `org_` prefix** → validates `org_name` claim (case-insensitive match)

```python
# By org ID — validates the org_id claim in the token
authorization_url = await auth0.start_interactive_login(
    StartInteractiveLoginOptions(organization="org_abc123")
)

# By org name — validates the org_name claim in the token (case-insensitive)
authorization_url = await auth0.start_interactive_login(
    StartInteractiveLoginOptions(organization="acme-corp")
)
```

> [!NOTE]
> Auth0 enforces that organization names cannot start with `org_`, so the prefix dispatch is unambiguous. When using org name, the SDK applies NFC Unicode normalization before comparison to prevent false rejections from visually identical characters with different byte representations.

## 3. Accept user invitations

When a user follows an invitation link, extract the `invitation` and `organization` parameters from the URL and pass them at login time. Auth0 validates the invitation ticket server-side — your application does not need to verify it.

The invitation URL Auth0 generates has this shape:
```
https://your-tenant.auth0.com/login?invitation={INVITATION_TOKEN}&organization={ORG_ID}&organization_name={ORG_NAME}
```

```python
@app.get("/auth/login")
async def login(request: Request, response: Response):
    invitation = request.query_params.get("invitation")
    organization = request.query_params.get("organization")

    options = StartInteractiveLoginOptions(organization=organization)
    if invitation:
        options.authorization_params = {"invitation": invitation}

    authorization_url = await auth0.start_interactive_login(
        options,
        store_options={"request": request, "response": response}
    )
    return RedirectResponse(url=authorization_url)
```

> [!NOTE]
> `organization` and `invitation` are forwarded to `/authorize`. Auth0 consumes the invitation ticket server-side — it is not stored in the encrypted transaction. If the ticket is expired or already used, `complete_interactive_login` raises `OrganizationInvitationError`.

## 4. Handling organization errors

The SDK raises typed exceptions for org-specific failure modes. Catch them in your callback handler to return meaningful responses to your users.

```python
from auth0_server_python.error import (
    OrganizationInvitationError,
    OrganizationAccessDeniedError,
    OrganizationRequiredError,
    OrganizationTokenValidationError,
)

@app.get("/auth/callback")
async def callback(request: Request, response: Response):
    try:
        result = await auth0.complete_interactive_login(
            str(request.url),
            store_options={"request": request, "response": response}
        )
        return RedirectResponse(url="/dashboard")
    except OrganizationAccessDeniedError:
        # User is not a member of the org, the connection is not enabled
        # for the org, or the org member quota has been exceeded.
        return RedirectResponse(url="/error?reason=not_org_member")
    except OrganizationRequiredError:
        # Configuration problem — invalid org format, Organizations feature
        # disabled, or the client is not configured for organizations.
        return RedirectResponse(url="/error?reason=org_config")
    except OrganizationInvitationError:
        # The invitation ticket is expired, already used, or invalid.
        return RedirectResponse(url="/error?reason=invitation_invalid")
    except OrganizationTokenValidationError:
        # The org_id or org_name in the returned token does not match
        # the organization that was requested at login.
        return RedirectResponse(url="/error?reason=org_mismatch")
```

| Exception | When raised |
|-----------|-------------|
| `OrganizationAccessDeniedError` | User not a member, connection not enabled for org, member quota exceeded |
| `OrganizationRequiredError` | Invalid org format, feature disabled, client not configured for orgs |
| `OrganizationInvitationError` | Invitation ticket expired, already used, or invalid |
| `OrganizationTokenValidationError` | `org_id` / `org_name` in the returned token does not match what was requested |

## 5. Reading organization data from the session

After a successful org login, `org_id` and `org_name` are available on the user object. Use `get_user()` to retrieve them on subsequent requests:

```python
user = await auth0.get_user(store_options={"request": request, "response": response})
if user:
    print(user.get("org_id"))    # e.g. "org_abc123"
    print(user.get("org_name"))  # e.g. "acme-corp"
```

You can also read them immediately from the `complete_interactive_login` result:

```python
result = await auth0.complete_interactive_login(
    str(request.url),
    store_options={"request": request, "response": response}
)
user = result["state_data"].get("user", {})
print(user.get("org_id"))
print(user.get("org_name"))
```

> [!NOTE]
> `org_name` is mutable — Auth0 allows renaming an organization after creation. Use `org_id` as the stable identifier for any persistent storage (e.g., mapping users to tenants in your database). Surface `org_name` only for display purposes.
