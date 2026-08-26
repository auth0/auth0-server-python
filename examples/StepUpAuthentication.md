# Step-Up Authentication (MFA)

Step-up authentication asks an already-logged-in user to re-authenticate with a stronger factor before a sensitive action (transferring funds, changing security settings, deleting data). The user keeps their session; you just require higher assurance for the one action.

With `auth0-server-python` you request step-up through the ordinary redirect flow — the same `start_interactive_login()` / `complete_interactive_login()` pair from [InteractiveLogin.md](./InteractiveLogin.md) — by adding an `acr_values` authorization parameter. Auth0's Universal Login handles the MFA challenge; when the user returns, you confirm it by reading the `acr` / `amr` claims from the session.

For the concepts, tenant requirements, and available `acr_values` policies, see the [Auth0 step-up authentication docs](https://auth0.com/docs/secure/multi-factor-authentication/step-up-authentication).

> [!NOTE]
> This is the right approach for apps using the **hosted login (Universal Login) redirect flow**. If your app drives an **embedded** MFA challenge itself (no redirect), use the MFA API via `client.mfa` instead — see [MFA.md](./MFA.md).

## Requesting Step-Up

Pass `acr_values` inside `authorization_params` when starting the login. Add `max_age: 0` to force a fresh authentication instead of silently reusing the current session, and use `app_state` to remember where to resume:

```python
from auth0_server_python.auth_types import StartInteractiveLoginOptions

# The OIDC "multi-factor" policy URI — asks Auth0 to enforce MFA for this login.
MFA_ACR = "http://schemas.openid.net/pape/policies/2007/06/multi-factor"

authorization_url = await server_client.start_interactive_login(
    StartInteractiveLoginOptions(
        authorization_params={
            "acr_values": MFA_ACR,
            "max_age": 0,  # force re-authentication; do not reuse the existing session
        },
        app_state={"returnTo": "/transfer"},  # resume this action after step-up
    ),
    store_options={"request": request, "response": response},
)
# Redirect the user to authorization_url.
```

## Verifying MFA Was Performed

After the user returns, complete the login as usual, then read the claims from the session. When the multi-factor policy is satisfied, Auth0 sets `acr` to the requested policy URI and includes `mfa` in the `amr` array. Treat step-up as satisfied when **either** signal is present:

```python
from typing import Optional

MFA_ACR = "http://schemas.openid.net/pape/policies/2007/06/multi-factor"

def mfa_completed(user: Optional[dict]) -> bool:
    if not user:
        return False
    return user.get("acr") == MFA_ACR or "mfa" in (user.get("amr") or [])
```

`acr` and `amr` are standard OIDC claims the SDK surfaces on the user object alongside `sub`, `email`, and the rest. They are only present when the corresponding authentication took place, so a plain login (no step-up) will not carry them.

## Full Example: Gating a Sensitive Action

`auth0-server-python` is framework-agnostic — it only reads and writes through the `request` / `response` objects you hand it via `store_options`. The handlers below are plain `async` functions; wire them into whatever framework you use. They gate a **Transfer Funds** action: if the session has not completed MFA, they return the authorization URL for your app to redirect to, then resume the transfer when the user returns.

```python
from typing import Optional

from auth0_server_python.auth_server.server_client import ServerClient
from auth0_server_python.auth_types import StartInteractiveLoginOptions

MFA_ACR = "http://schemas.openid.net/pape/policies/2007/06/multi-factor"

server_client = ServerClient(
    domain="YOUR_AUTH0_DOMAIN",
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    secret="YOUR_SECRET",
    authorization_params={"redirect_uri": "http://localhost:3000/auth/callback"},
    # ... your configured transaction_store and state_store
)


def mfa_completed(user: Optional[dict]) -> bool:
    if not user:
        return False
    return user.get("acr") == MFA_ACR or "mfa" in (user.get("amr") or [])


# `request` and `response` are your framework's objects (or whatever your
# configured transaction/state store reads cookies from and writes them to).
async def handle_transfer(request, response):
    store_options = {"request": request, "response": response}

    user = await server_client.get_user(store_options=store_options)
    if not mfa_completed(user):
        # Not stepped up yet — return this URL and have your app redirect to it.
        return await server_client.start_interactive_login(
            StartInteractiveLoginOptions(
                authorization_params={"acr_values": MFA_ACR, "max_age": 0},
                app_state={"returnTo": "/transfer"},
            ),
            store_options=store_options,
        )

    # MFA satisfied for this session — safe to run the sensitive action.
    run_transfer()
    return {"status": "transfer complete"}


# `callback_url` is the full URL Auth0 redirected back to, including the
# `?code=...&state=...` query string.
async def handle_callback(callback_url, request, response):
    store_options = {"request": request, "response": response}

    result = await server_client.complete_interactive_login(
        callback_url, store_options=store_options
    )
    # Return where to send the user next; your app performs the redirect.
    return (result.get("app_state") or {}).get("returnTo", "/")
```

> [!NOTE]
> The redirect itself is framework-specific — these handlers return the URL to redirect to, and your app issues the actual HTTP redirect (e.g. a `302`/`303`). `max_age: 0` matters: without it, a user who authenticated moments ago may be returned straight to your callback without a fresh MFA prompt.
