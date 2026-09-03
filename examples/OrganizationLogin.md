# Organization Login

[Auth0 Organizations](https://auth0.com/docs/organizations) lets you manage business customers and partner companies as distinct entities with their own membership, branding, and login policies.

`auth0-server-python` supports two patterns:

- **Dedicated-org** - set `organization` on `ServerClient` once; every login is scoped to that org.
- **Multi-org** - pass `organization` per login call; one client serves many tenants.

Both patterns go through the same `start_interactive_login()` / `complete_interactive_login()` pair from [InteractiveLogin.md](./InteractiveLogin.md). The SDK validates the `org_id` or `org_name` claim in the returned token automatically at callback.

For tenant-level setup (enabling Organizations, configuring connections, and setting display name) see [Auth0 Organizations docs](https://auth0.com/docs/organizations).

## Dedicated-Org Login

Set `organization` on `ServerClient` to scope every login to a single org:

```python
from auth0_server_python.auth_server.server_client import ServerClient

auth0 = ServerClient(
    domain="YOUR_AUTH0_DOMAIN",
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    secret="YOUR_SECRET",
    organization="org_abc123",
    authorization_params={"redirect_uri": "http://localhost:3000/auth/callback"},
    # ... your configured transaction_store and state_store
)

# `organization` is applied automatically to every start_interactive_login call.
authorization_url = await auth0.start_interactive_login(
    store_options={"request": request, "response": response}
)
```

`organization` accepts either an org ID (with the `org_` prefix) or a human-readable org name. The SDK validates the corresponding `org_id` or `org_name` claim in the returned ID token.

## Multi-Org Login

Pass `organization` per login call when a single app serves multiple orgs. The value comes from your own routing logic (subdomain, path segment, user selection) - never pass it unvalidated from user-controlled input:

```python
from auth0_server_python.auth_server.server_client import ServerClient
from auth0_server_python.auth_types import StartInteractiveLoginOptions

auth0 = ServerClient(
    domain="YOUR_AUTH0_DOMAIN",
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    secret="YOUR_SECRET",
    authorization_params={"redirect_uri": "http://localhost:3000/auth/callback"},
    # ... your configured transaction_store and state_store
)

# Resolve the org from your own routing (subdomain, path, user selection, etc.)
org_id = resolve_org_for_request(request)  # your own logic; never trust raw user input

authorization_url = await auth0.start_interactive_login(
    StartInteractiveLoginOptions(organization=org_id),
    store_options={"request": request, "response": response},
)
```

> [!IMPORTANT]
> Validate that the `organization` value comes from a trusted source - a lookup in your own data store, a resolved subdomain, or a server-side mapping. Never pass a raw query parameter or form value directly.

## Accepting an Invitation

When a user follows an org invitation link, Auth0 appends `organization` and `invitation` to the URL. Extract both and pass them as typed fields on `StartInteractiveLoginOptions`:

```python
from auth0_server_python.auth_types import StartInteractiveLoginOptions

# `organization` and `invitation` arrive as query parameters on the invitation link.
authorization_url = await auth0.start_interactive_login(
    StartInteractiveLoginOptions(
        organization=request.query_params.get("organization"),
        invitation=request.query_params.get("invitation"),
    ),
    store_options={"request": request, "response": response},
)
```

The `invitation` parameter is consumed by Auth0 during the login and is not present in the session after callback.

> [!NOTE]
> The `organization` parameter on an invitation link is set by Auth0 and refers to a specific org ID - it is safe to pass it through here. However, do not allow users to supply `organization` or `invitation` values from other sources without validation.

## Handling Organization Errors

Org-related failures arrive at the callback URL as OAuth error responses. The SDK surfaces them as typed exceptions:

```python
from auth0_server_python.error import ApiError, MissingTransactionError, OrganizationTokenValidationError

try:
    result = await auth0.complete_interactive_login(
        str(request.url),
        store_options={"request": request, "response": response},
    )
    return_to = (result.get("app_state") or {}).get("returnTo", "/")
except OrganizationTokenValidationError:
    return_to = "/error?reason=org_mismatch"
except MissingTransactionError:
    return_to = "/error?reason=expired_or_replayed"
except ApiError as e:
    return_to = f"/error?reason={e.code}"
```

| Exception | When raised |
|-----------|-------------|
| `OrganizationTokenValidationError` | `org_id` / `org_name` in the returned token does not match what was requested |
| `MissingTransactionError` | The login transaction has expired or was already consumed (e.g. page reload or replayed callback) |
| `ApiError` | Auth0 rejected the authorization request; inspect `e.code` and `e.message` for the raw OAuth error |

Common `ApiError.code` values:

| `e.code` | Typical cause |
|---|---|
| `access_denied` | User is not a member, connection not enabled for org, or member quota exceeded |
| `invalid_request` | Invalid org format, feature disabled, client not configured for orgs, or expired / invalid invitation ticket |

## Reading Organization Data from the Session

After a successful org login, `org_id` is present in the user object. `org_name` is also present when the org has the display-name feature enabled:

```python
user = await auth0.get_user(store_options={"request": request, "response": response})
if user:
    org_id = user.get("org_id")    # always present; use as the stable identifier
    org_name = user.get("org_name")  # present when org display name is enabled
```

Use `org_id` (not `org_name`) as a stable identifier in your own data store - org names can be changed.

## Full Example: Multi-Org App

`auth0-server-python` is framework-agnostic - it reads and writes only through the `request` / `response` objects you pass via `store_options`. The handlers below are plain `async` functions. Wire them into whatever framework you use. They model a multi-org app that resolves the current org from the subdomain and gates the dashboard on membership:

```python
from typing import Optional

from auth0_server_python.auth_server.server_client import ServerClient
from auth0_server_python.auth_types import StartInteractiveLoginOptions
from auth0_server_python.error import ApiError, MissingTransactionError, OrganizationTokenValidationError

auth0 = ServerClient(
    domain="YOUR_AUTH0_DOMAIN",
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    secret="YOUR_SECRET",
    authorization_params={"redirect_uri": "http://localhost:3000/auth/callback"},
    # ... your configured transaction_store and state_store
)

# Map your subdomains (or any trusted source) to org IDs.
SUBDOMAIN_TO_ORG: dict = {
    "acme": "org_acme123",
    "globex": "org_globex456",
}


def resolve_org(hostname: str) -> Optional[str]:
    subdomain = hostname.split(".")[0]
    return SUBDOMAIN_TO_ORG.get(subdomain)


# `request` and `response` are your framework's objects (or whatever your
# configured transaction/state store reads cookies from and writes them to).
async def handle_login(request, response):
    store_options = {"request": request, "response": response}
    org_id = resolve_org(request.headers.get("host", ""))
    if org_id is None:
        # No org is mapped to this host. Redirect to an error page or fall back
        # to a non-org login depending on your app's requirements.
        raise ValueError(f"No organization mapped for host: {request.headers.get('host', '')}")

    return await auth0.start_interactive_login(
        StartInteractiveLoginOptions(
            organization=org_id,
            app_state={"returnTo": "/dashboard"},
        ),
        store_options=store_options,
    )


# `callback_url` is the full URL Auth0 redirected back to, including `?code=...&state=...`.
async def handle_callback(callback_url: str, request, response):
    store_options = {"request": request, "response": response}
    try:
        result = await auth0.complete_interactive_login(callback_url, store_options=store_options)
        return (result.get("app_state") or {}).get("returnTo", "/")
    except OrganizationTokenValidationError:
        return "/error?reason=org_mismatch"
    except MissingTransactionError:
        return "/error?reason=expired_or_replayed"
    except ApiError as e:
        return f"/error?reason={e.code}"


async def handle_dashboard(request, response):
    store_options = {"request": request, "response": response}
    user = await auth0.get_user(store_options=store_options)
    if not user:
        return None  # redirect to login

    org_id = user.get("org_id")
    org_name = user.get("org_name")

    # Verify the session belongs to the org mapped to the current host. Without
    # this check, a wildcard cookie (e.g. Domain=.yourapp.com) lets a session
    # from acme.yourapp.com access globex.yourapp.com data.
    expected_org = resolve_org(request.headers.get("host", ""))
    if org_id != expected_org:
        return None  # org mismatch - redirect to login for the correct org

    return {"user": user, "org_id": org_id, "org_name": org_name}
```

## Wiring the Redirect (FastAPI)

The handlers above return the URL to redirect to. Your framework issues the redirect. In FastAPI:

```python
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse

app = FastAPI()


@app.get("/auth/login")
async def login(request: Request, response: Response):
    authorization_url = await handle_login(request, response)
    return RedirectResponse(authorization_url, 303)


@app.get("/auth/callback")
async def callback(request: Request, response: Response):
    return_to = await handle_callback(str(request.url), request, response)
    return RedirectResponse(return_to, 303)


@app.get("/dashboard")
async def dashboard(request: Request, response: Response):
    data = await handle_dashboard(request, response)
    if data is None:
        return RedirectResponse("/auth/login", 303)
    return JSONResponse(data)
```

> [!NOTE]
> The invitation flow wires in the same way - add a `/auth/login` handler that reads `organization` and `invitation` from the query string and passes them to `start_interactive_login` via `StartInteractiveLoginOptions`.
