# Interactive Login

Interactive login in `auth0‑server‑python` is a two‑step process. First, you start the login flow by obtaining an authorization URL; then, after the user authenticates at Auth0 and is redirected back, you complete the login flow to exchange the authorization code for tokens.

This guide covers how to customize the authorization parameters, pass custom app state, enable **Pushed Authorization Requests (PAR)** and **Rich Authorization Requests (RAR)**, supply store options, and log in to an organization.

## 1. Starting Interactive Login

### Configuring the Redirect URI

Interactive login begins by configuring a redirect_uri—the URL Auth0 will use to send the user back after authentication. For example, when instantiating your core `ServerClient`:

```python
from auth0_server_python.auth_server.server_client import ServerClient

server_client = ServerClient(
    domain="YOUR_AUTH0_DOMAIN",
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    secret="YOUR_SECRET",
    authorization_params={
        "redirect_uri":"http://localhost:3000/auth/callback",
    }
)
```
Now call `start_interactive_login()` to obtain the authorization URL and redirect the user:
```python
authorization_url = await server_client.start_interactive_login()
```
## 2. Passing Authorization Params
You can customize the parameters sent to Auth0's `/authorize` endpoint in two ways:

### Global Configuration

When creating your ServerClient, you can specify default parameters:

```python
server_client = ServerClient(
    domain="YOUR_AUTH0_DOMAIN",
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    redirect_uri="http://localhost:3000/auth/callback",
    secret="YOUR_SECRET",
    authorization_params={
        "scope": " your scopes",
        "audience": "urn:custom:api",
    }
)
```
### Dynamic Configuration Per Call
You can also override or add parameters when calling `start_interactive_login()`:
```python
from auth0_server_python.auth_types import StartInteractiveLoginOptions

authorization_url = await server_client.start_interactive_login(
    StartInteractiveLoginOptions(
        authorization_params={
            "scope": "openid profile email",
            "audience": "urn:custom:api",
            "foo": "bar"  # arbitrary custom parameter
        }
    )
)
```
> [!NOTE]
> Any parameter specified here will override the corresponding global configuration.

## 3. Passing App State to Track State During Login

The `app_state` parameter allows you to pass custom state (for example, a return URL) that is later available when the login process completes.

```python
# Start interactive login with custom app state:
from auth0_server_python.auth_types import StartInteractiveLoginOptions

authorize_url = await server_client.start_interactive_login(
    StartInteractiveLoginOptions(app_state={"returnTo": "http://localhost:3000/dashboard"})
)

# Later, after completing login:
result = await server_client.complete_interactive_login(callback_url)
print(result.get("app_state").get("returnTo"))  # Should output: http://localhost:3000/dashboard
```
> [!NOTE]
>- `authorize_url` is the URL for Auth0's /authorize endpoint (or a URL built from PAR, if enabled).
>- `callback_url` is the URL Auth0 redirects back to after authentication.

## 4. Using Pushed Authorization Requests (PAR)

To enable PAR, simply set the flag in your interactive login options. When enabled, the SDK will send an HTTP POST request with the authorization parameters to the PAR endpoint (retrieved from OIDC metadata) and use the returned `request_uri` to build the final authorization URL.
```python
# Enable PAR dynamically for a login call:
from auth0_server_python.auth_types import StartInteractiveLoginOptions

authorization_url = await server_client.start_interactive_login(
    StartInteractiveLoginOptions(pushed_authorization_requests=True)
)
```
>[!IMPORTANT]
> Using PAR requires that your Auth0 tenant is configured to support it. Refer to Auth0's documentation for details.

## 5. Using Pushed Authorization Requests and Rich Authorization Requests (RAR)

When using PAR, you can also supply Rich Authorization Request details by including an `authorization_details` field in the `authorization_params`:
```python
import json

from auth0_server_python.auth_types import StartInteractiveLoginOptions

authorization_url = await server_client.start_interactive_login(
    StartInteractiveLoginOptions(
        pushed_authorization_requests=True,
        authorization_params={
            "authorization_details": json.dumps([{
                "type": "your_type",
                "additional_field": "value"
            }])
        }
    )
)
```
After completing the interactive login, the SDK will expose the `authorization_details` in the result:
```python
result = await server_client.complete_interactive_login(callback_url)
print(result.get("authorization_details"))
```
>[!NOTE]
>Both PAR and RAR require that these features are enabled in your Auth0 dashboard.

## 6. Passing Store Options
Most methods in the SDK accept a second argument called `store_options`. This dictionary should include the HTTP Request and Response objects (or equivalent) that the store uses to manage cookies and session data.
```python
store_options = {"request": request, "response": response}
authorization_url = await server_client.start_interactive_login(store_options=store_options)
```
This enables the SDK to correctly read and set cookies for session management.

## 7.  Completing Interactive Login

After the user is redirected back to your callback URL from Auth0, you call `complete_interactive_login()` to finalize the authentication process. This method extracts the authorization code from the URL, exchanges it for tokens, and returns session data (including any app_state you passed originally, and—if using RAR—the `authorization_details`).
```python
result = await server_client.complete_interactive_login(callback_url, store_options={"request": request, "response": response})
print(result.get("app_state").get("returnTo"))           # Custom app state
print(result.get("authorization_details"))               # Rich Authorization Requests details (if any)

```

>[!NOTE]
>The `callback_url` must include the necessary parameters (`state` and `code`) that Auth0 sends upon successful authentication.

## 8. Organizations

[Auth0 Organizations](https://auth0.com/docs/organizations) lets you manage teams, business customers, and partner companies as distinct entities with their own login flows and membership.

### Logging in to an organization

Set `organization` on `ServerClient` to enforce it for every login (dedicated-org), or pass it per login via `StartInteractiveLoginOptions` (multi-org):

```python
from auth0_server_python.auth_server.server_client import ServerClient
from auth0_server_python.auth_types import StartInteractiveLoginOptions

# Dedicated-org: every login enforces this organization
auth0 = ServerClient(
    domain="YOUR_AUTH0_DOMAIN",
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    secret="YOUR_SECRET",
    organization="org_abc123",
    authorization_params={"redirect_uri": "http://localhost:3000/auth/callback"}
)

# Multi-org: pass organization per login
authorization_url = await auth0.start_interactive_login(
    StartInteractiveLoginOptions(organization="org_xyz789"),
    store_options={"request": request, "response": response}
)
```

`organization` accepts either an org ID (`org_` prefix) or an org name. The SDK validates the corresponding `org_id` or `org_name` claim in the returned token automatically at callback.

> [!IMPORTANT]
> In the multi-org pattern, validate that the `organization` value comes from a trusted source — never pass it unvalidated directly from user input.

### Accepting an invitation

When a user follows an invitation link, extract `organization` and `invitation` from the URL and pass them as typed fields:

```python
@app.get("/auth/login")
async def login(request: Request, response: Response):
    authorization_url = await auth0.start_interactive_login(
        StartInteractiveLoginOptions(
            organization=request.query_params.get("organization"),
            invitation=request.query_params.get("invitation"),
        ),
        store_options={"request": request, "response": response}
    )
    return RedirectResponse(url=authorization_url)
```

### Handling organization errors

Auth0 returns organization errors as standard OAuth error responses (`error` + `error_description`). The SDK surfaces these as `ApiError`, preserving the raw values so you can branch on `error.code`:

```python
from auth0_server_python.error import ApiError, OrganizationTokenValidationError

@app.get("/auth/callback")
async def callback(request: Request, response: Response):
    try:
        result = await auth0.complete_interactive_login(
            str(request.url),
            store_options={"request": request, "response": response}
        )
        return RedirectResponse(url="/dashboard")
    except OrganizationTokenValidationError:
        return RedirectResponse(url="/error?reason=org_mismatch")
    except ApiError as e:
        return RedirectResponse(url=f"/error?reason={e.code}")
```

| Exception | When raised |
|-----------|-------------|
| `OrganizationTokenValidationError` | `org_id` / `org_name` in the returned token does not match what was requested |
| `ApiError` | Auth0 rejected the authorization request — inspect `error.code` and `error.message` for the raw OAuth error and description |

Common `ApiError.code` values for org flows:

| `error.code` | Typical cause |
|---|---|
| `access_denied` | User not a member, connection not enabled for org, member quota exceeded |
| `invalid_request` | Invalid org format, feature disabled, client not configured for orgs, expired or invalid invitation ticket |

### Reading organization data from the session

After a successful org login, `org_id` is always present in the token. `org_name` is also present when the organization has the org name feature enabled:

```python
user = await auth0.get_user(store_options={"request": request, "response": response})
if user:
    print(user.get("org_id"))    # always present; use as stable identifier
    print(user.get("org_name"))  # present when org name is enabled
```
