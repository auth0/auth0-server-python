# Custom Token Exchange

Custom Token Exchange allows you to exchange tokens from external identity providers or legacy authentication systems for Auth0 tokens without browser redirects. This implements **OAuth 2.0 Token Exchange** ([RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693)).

> **NOTE**: For complete documentation on Custom Token Exchange, configuration requirements, and detailed use cases, see the [official Auth0 documentation](https://auth0.com/docs/authenticate/custom-token-exchange).

## 1. Basic Token Exchange

Exchange a custom token for Auth0 tokens without creating a user session.

```python
from auth0_server_python.auth_server.server_client import ServerClient
from auth0_server_python.auth_types import CustomTokenExchangeOptions

# Initialize the client
auth0 = ServerClient(
    domain="<AUTH0_DOMAIN>",
    client_id="<AUTH0_CLIENT_ID>",
    client_secret="<AUTH0_CLIENT_SECRET>",
    secret="<AUTH0_SECRET>"
)

# Exchange a custom token
response = await auth0.custom_token_exchange(
    CustomTokenExchangeOptions(
        subject_token="custom-token-from-external-system",
        subject_token_type="urn:acme:mcp-token",
        audience="https://api.example.com",
        scope="read:data write:data"
    )
)

# Access the exchanged tokens
print(f"Access Token: {response.access_token}")
print(f"Expires In: {response.expires_in} seconds")
if response.id_token:
    print(f"ID Token: {response.id_token}")
```

## 2. Login with Token Exchange

Exchange a custom token AND establish a user session.

```python
from auth0_server_python.auth_types import LoginWithCustomTokenExchangeOptions
from fastapi import Request, Response

# Exchange token and create session
result = await auth0.login_with_custom_token_exchange(
    LoginWithCustomTokenExchangeOptions(
        subject_token="custom-token-from-external-system",
        subject_token_type="urn:acme:mcp-token",
        audience="https://api.example.com"
    ),
    store_options={"request": request, "response": response}
)

# User is now logged in
user = result.state_data["user"]
print(f"User logged in: {user['sub']}")
```

> **TIP**: Use `login_with_custom_token_exchange()` when you need both token exchange and session management (e.g., user migration flows). Use `custom_token_exchange()` for pure token exchange scenarios (e.g., service-to-service authentication).

## 3. Actor Tokens (Delegation)

Enable delegation scenarios where one party acts on behalf of a user. The acting party is supplied via `actor_token`, and Auth0 records it in the [`act` claim](https://datatracker.ietf.org/doc/html/rfc8693#section-4.1) on the issued tokens.

```python
# Service acting on behalf of a user
response = await auth0.custom_token_exchange(
    CustomTokenExchangeOptions(
        subject_token="user-access-token",
        subject_token_type="urn:ietf:params:oauth:token-type:access_token",
        actor_token="service-access-token",
        actor_token_type="urn:ietf:params:oauth:token-type:access_token",
        audience="https://api.example.com"
    )
)

# The actor claim is surfaced on the response. It may nest for delegation chains.
if response.act:
    print(f"Acting party: {response.act['sub']}")
```

> **NOTE**: `response.act` is read from the ID token. Auth0 writes the same `act` claim onto the issued access token as well, so they reflect the same acting party. The access token may be opaque, in which case `act` cannot be read off it directly - the ID token is where you read it.

When you establish a session with `login_with_custom_token_exchange()`, the `act` claim is persisted on the session user and can be read back later via `get_user()`:

```python
result = await auth0.login_with_custom_token_exchange(
    LoginWithCustomTokenExchangeOptions(
        subject_token="user-access-token",
        subject_token_type="urn:ietf:params:oauth:token-type:access_token",
        actor_token="service-access-token",
        actor_token_type="urn:ietf:params:oauth:token-type:access_token",
    ),
    store_options={"request": request, "response": response}
)

user = result.state_data["user"]
if user.get("act"):
    print(f"Acting party: {user['act']['sub']}")
```

> **NOTE**: When an `actor_token` is present, Auth0 does not issue a refresh token (the `offline_access` scope is dropped). A subsequent refresh-token grant therefore cannot re-emit the `act` claim, so the acting party is fixed at exchange time.

## 4. Custom Authorization Parameters

Pass additional parameters to the token endpoint.

```python
response = await auth0.custom_token_exchange(
    CustomTokenExchangeOptions(
        subject_token="custom-token",
        subject_token_type="urn:acme:mcp-token",
        audience="https://api.example.com",
        authorization_params={
            "custom_field": "custom_value"
        }
    )
)
```

> **NOTE**: Critical parameters (`grant_type`, `client_id`, `subject_token`, `subject_token_type`) cannot be overridden via `authorization_params` for security reasons.

## 5. Organization Support

Specify an organization when exchanging tokens.

```python
response = await auth0.custom_token_exchange(
    CustomTokenExchangeOptions(
        subject_token="custom-token",
        subject_token_type="urn:acme:mcp-token",
        audience="https://api.example.com",
        organization="org_abc1234"
    )
)
```

## 6. Error Handling

```python
from auth0_server_python.error import CustomTokenExchangeError

try:
    response = await auth0.custom_token_exchange(
        CustomTokenExchangeOptions(
            subject_token="token",
            subject_token_type="urn:acme:mcp-token"
        )
    )
except CustomTokenExchangeError as e:
    print(f"Exchange failed: {e.code} - {e.message}")
```

### Common Error Codes

- `INVALID_TOKEN_FORMAT`: Token is empty, whitespace-only, or has "Bearer " prefix
- `MISSING_ACTOR_TOKEN_TYPE`: `actor_token` provided without `actor_token_type`
- `MISSING_ACTOR_TOKEN`: `actor_token_type` provided without `actor_token`
- `TOKEN_EXCHANGE_FAILED`: General token exchange failure
- `INVALID_RESPONSE`: Auth0 returned a non-JSON response

## 7. Token Type URIs

Use standard URNs when possible:

```python
# Standard token types
"urn:ietf:params:oauth:token-type:jwt"            # JWT tokens
"urn:ietf:params:oauth:token-type:access_token"   # OAuth access tokens
"urn:ietf:params:oauth:token-type:id_token"       # OpenID Connect ID tokens
"urn:ietf:params:oauth:token-type:refresh_token"  # OAuth refresh tokens

# Custom token types (use your own namespace)
"urn:acme:mcp-token"
"urn:company:legacy-token"
```

## 8. Impersonation via Session Transfer (STT)

Custom Token Exchange can also mint a **Session Transfer Token (STT)** instead of an API access token. An STT lets an initiator app (for example a support console) log an agent into a target web app **as** a customer, with the agent recorded in the `act` claim - so a support engineer can reproduce a customer's exact experience without their password.

This is a two-role, two-hop flow:

- **Initiator** (the agent's app) mints the STT and redirects with it. This is where the new SDK methods live.
- **Target** (the customer's app) forwards the STT to `/authorize` on a normal interactive login, which establishes the impersonated session.

The STT is opaque, single-use, and short-lived (~60s). The SDK requests it and helps build the redirect - it never decodes or stores it.

### Initiator: request an STT and build the redirect

```python
from auth0_server_python.auth_server.server_client import ServerClient
from auth0_server_python.error import CustomTokenExchangeError

# Mint the STT. The audience (urn:{domain}:session_transfer), grant type, and the actor are
# set by the SDK - the actor is sourced from the logged-in agent's session.
result = await auth0.request_session_transfer_token(
    subject_token=subject_token,            # your proof of which customer to impersonate
    subject_token_type="urn:acme:customer-subject",
    organization=None,                      # optional; forwarded to the redirect
    store_options={"request": request, "response": None},
)

# result.session_transfer_token is the opaque, one-shot STT (~60s). Never store it.
redirect_url = auth0.build_session_transfer_redirect(
    "https://customer-app.example.com/auth/login", result, organization=None
)
return RedirectResponse(redirect_url)       # your framework performs the redirect
```

`SessionTransferTokenResult` carries `session_transfer_token`, `issued_token_type` (the session-transfer URN - the field to branch on), `expires_in`, and an informational `token_type` (`N_A`). There is no `act` on this result; `act` appears later, on the target session.

> **NOTE**: An actor is mandatory - an STT is only issued when the Action set one. By default the SDK sources the actor from the logged-in agent's session ID token, refreshing it when expired. If the agent is not logged in (no usable session ID token and none can be refreshed), the call fails client-side with `ACTOR_UNAVAILABLE` before any network request.

> **NOTE**: To use your own actor token instead of the session, pass `actor_token` (and optionally `actor_token_type`, which defaults to the ID token URN). An explicit `actor_token` takes precedence and the session is not read at all. It must be an **unexpired, asymmetrically-signed JWT** (RS256 or PS256) - an Auth0 session ID token satisfies this; an HS256 or expired token is rejected by the server.
>
> ```python
> result = await auth0.request_session_transfer_token(
>     subject_token=subject_token,
>     subject_token_type="urn:acme:customer-subject",
>     actor_token=agent_id_token,   # explicit override - session is not used
>     store_options={"request": request, "response": None},
> )
> ```

### Target: forward the STT to `/authorize`

On the target, the STT rides through your normal login. `start_interactive_login` forwards arbitrary authorization parameters to `/authorize`, so your login route just passes `session_transfer_token` (and `organization`, when the STT was issued in an org context) straight through:

```python
from auth0_server_python.auth_types import StartInteractiveLoginOptions

url = await auth0.start_interactive_login(
    StartInteractiveLoginOptions(authorization_params={
        "session_transfer_token": request.query_params["session_transfer_token"],
        # "organization": org,   # when the STT was issued in an org context
    }),
    store_options={"request": request, "response": None},
)
return RedirectResponse(url)
```

After the callback completes, read the acting party off the session user - the same way as the [Actor Tokens (Delegation)](#3-actor-tokens-delegation) section above:

```python
session = await auth0.get_session(store_options={"request": request, "response": None})
act = (session or {}).get("user", {}).get("act")
if act:
    print(f"Impersonated by: {act['sub']}")   # drive an impersonation banner, etc.
```

> **NOTE**: Both clients need one-time configuration through the Auth0 Dashboard or Management API. The issuing (initiator) client must be allowed to create session transfer tokens. The redeeming (target) client must be allowed to accept delegated-access sessions and to receive the token as a query parameter. See the [Auth0 documentation](https://auth0.com/docs/authenticate/custom-token-exchange) for the exact client settings.

> **NOTE**: `build_session_transfer_redirect` attaches a single-use credential to `target_login_url`, so that URL must be a trusted, app-controlled value - never one derived from untrusted input (such as a user-supplied `returnTo`), which could leak the token to an attacker host.

> **NOTE**: The impersonation session is hard-capped at 2 hours and cannot mint a refresh token (`offline_access` is dropped when an actor is present). To continue past that, re-run the flow.

### STT error codes

- `ACTOR_UNAVAILABLE`: no usable actor token (client-side; raised before any network call)
- `SETACTOR_REQUIRED`: an STT was requested but the Action did not call `setActor` (server 400)
- `SESSION_TRANSFER_DISABLED`: the session-transfer feature is off for the tenant/client (server 400)

## Additional Resources

- [Auth0 Custom Token Exchange Documentation](https://auth0.com/docs/authenticate/custom-token-exchange)
- [RFC 8693 - OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
