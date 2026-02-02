# Custom Token Exchange

Custom token exchange allows you to exchange tokens from external identity providers or legacy authentication systems for Auth0 tokens. This is implemented according to **OAuth 2.0 Token Exchange** ([RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693)).

## Table of Contents

- [Basic Token Exchange](#basic-token-exchange)
- [Login with Token Exchange](#login-with-token-exchange)
- [Advanced Scenarios](#advanced-scenarios)
  - [Actor Tokens (Delegation)](#actor-tokens-delegation)
  - [Custom Authorization Parameters](#custom-authorization-parameters)
- [Error Handling](#error-handling)
- [Security Considerations](#security-considerations)

---

## Basic Token Exchange

The `custom_token_exchange()` method exchanges a custom token for Auth0 tokens without creating a user session. This is useful when you need to obtain Auth0 tokens programmatically.

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
        subject_token_type="urn:acme:mcp-token",  # Your custom token type
        audience="https://api.example.com",
        scope="read:data write:data"
    )
)

# Use the exchanged Auth0 tokens
print(f"Access Token: {response.access_token}")
print(f"Expires In: {response.expires_in} seconds")
print(f"Scope: {response.scope}")

# If an ID token is returned
if response.id_token:
    print(f"ID Token: {response.id_token}")

# If a refresh token is returned
if response.refresh_token:
    print(f"Refresh Token: {response.refresh_token}")
```

### Parameters

- **`subject_token`** (required): The token being exchanged from your external system
- **`subject_token_type`** (required): A URN identifying the token format (e.g., `urn:acme:mcp-token`, `urn:ietf:params:oauth:token-type:jwt`)
- **`audience`** (optional): Target API or service identifier
- **`scope`** (optional): Space-delimited list of OAuth scopes
- **`actor_token`** (optional): Token representing the acting party (for delegation scenarios)
- **`actor_token_type`** (optional): Type of actor token (required if `actor_token` is provided)
- **`authorization_params`** (optional): Additional OAuth parameters

---

## Login with Token Exchange

The `login_with_custom_token_exchange()` method combines token exchange with session management, establishing a logged-in user session after exchanging the token.

```python
from auth0_server_python.auth_types import LoginWithCustomTokenExchangeOptions
from fastapi import FastAPI, Request, Response
from starlette.responses import RedirectResponse

app = FastAPI()

@app.get("/auth/exchange-login")
async def exchange_login(request: Request, response: Response):
    # Exchange custom token and create user session
    result = await auth0.login_with_custom_token_exchange(
        LoginWithCustomTokenExchangeOptions(
            subject_token="custom-token-from-external-system",
            subject_token_type="urn:acme:mcp-token",
            audience="https://api.example.com"
        ),
        store_options={"request": request, "response": response}
    )

    # Session is now established
    user = result.state_data["user"]
    print(f"User logged in: {user['sub']}")

    # Redirect to dashboard
    return RedirectResponse(url="/dashboard")
```

### Use Cases

- **Migration from Legacy Systems**: Exchange tokens during migration to Auth0
- **Partner SSO**: Accept tokens from partner identity providers
- **Custom Authentication Flows**: Integrate proprietary authentication mechanisms

---

## Advanced Scenarios

### Actor Tokens (Delegation)

Actor tokens enable delegation scenarios where one service acts on behalf of a user.

```python
from auth0_server_python.auth_types import CustomTokenExchangeOptions

# Service-to-service delegation
response = await auth0.custom_token_exchange(
    CustomTokenExchangeOptions(
        subject_token="user-access-token",
        subject_token_type="urn:ietf:params:oauth:token-type:access_token",
        actor_token="service-access-token",
        actor_token_type="urn:ietf:params:oauth:token-type:access_token",
        audience="https://api.example.com"
    )
)

# The returned token represents the service acting on behalf of the user
```

### Custom Authorization Parameters

You can pass additional OAuth parameters using `authorization_params`:

```python
response = await auth0.custom_token_exchange(
    CustomTokenExchangeOptions(
        subject_token="custom-token",
        subject_token_type="urn:acme:mcp-token",
        audience="https://api.example.com",
        authorization_params={
            "custom_field": "custom_value",
            "organization": "org_123"
        }
    )
)
```

> **Note**: Critical parameters (`grant_type`, `client_id`, `subject_token`, `subject_token_type`) cannot be overridden via `authorization_params` for security reasons.

---

## Error Handling

The SDK provides specific error types for token exchange failures:

```python
from auth0_server_python.error import (
    CustomTokenExchangeError,
    CustomTokenExchangeErrorCode
)

try:
    response = await auth0.custom_token_exchange(
        CustomTokenExchangeOptions(
            subject_token="invalid-token",
            subject_token_type="urn:acme:mcp-token"
        )
    )
except CustomTokenExchangeError as e:
    if e.code == CustomTokenExchangeErrorCode.INVALID_TOKEN_FORMAT:
        print(f"Token format error: {e.message}")
    elif e.code == CustomTokenExchangeErrorCode.TOKEN_EXCHANGE_FAILED:
        print(f"Exchange failed: {e.message}")
    elif e.code == CustomTokenExchangeErrorCode.INVALID_RESPONSE:
        print(f"Invalid response from Auth0: {e.message}")
    else:
        print(f"Error: {e.code} - {e.message}")
```

### Common Error Codes

| Error Code | Description |
|------------|-------------|
| `INVALID_TOKEN_FORMAT` | Token is empty, whitespace-only, or has "Bearer " prefix |
| `MISSING_ACTOR_TOKEN_TYPE` | `actor_token` provided without `actor_token_type` |
| `TOKEN_EXCHANGE_FAILED` | General token exchange failure (check `message` for details) |
| `INVALID_RESPONSE` | Auth0 returned a non-JSON response |

### Validation Errors

The SDK validates tokens before sending them to Auth0:

```python
# ❌ These will fail validation:
CustomTokenExchangeOptions(
    subject_token="   ",  # Empty/whitespace
    subject_token_type="urn:acme:token"
)

CustomTokenExchangeOptions(
    subject_token="Bearer abc123",  # Has "Bearer " prefix
    subject_token_type="urn:ietf:params:oauth:token-type:access_token"
)

CustomTokenExchangeOptions(
    subject_token="token",
    subject_token_type="urn:acme:token",
    actor_token="actor-token",
    actor_token_type=None  # Missing actor_token_type
)
```

---

## Security Considerations

### 1. Token Format

- **DO NOT** include the "Bearer " prefix in tokens
- Tokens should be sent exactly as received from the external system
- The SDK will validate token format before sending to Auth0

### 2. Subject Token Types

Use standard URNs when possible:
- `urn:ietf:params:oauth:token-type:jwt` - JWT tokens
- `urn:ietf:params:oauth:token-type:access_token` - OAuth access tokens
- `urn:ietf:params:oauth:token-type:refresh_token` - OAuth refresh tokens
- `urn:ietf:params:oauth:token-type:id_token` - OpenID Connect ID tokens
- `urn:ietf:params:oauth:token-type:saml2` - SAML 2.0 assertions

For custom token formats, use your own namespace:
- `urn:acme:mcp-token`
- `urn:example:legacy-token`

### 3. Scope Limitation

Request only the minimum required scopes:

```python
# ✅ Good - minimal scopes
response = await auth0.custom_token_exchange(
    CustomTokenExchangeOptions(
        subject_token="token",
        subject_token_type="urn:acme:mcp-token",
        scope="read:profile"  # Only what's needed
    )
)

# ⚠️ Avoid - overly broad scopes
response = await auth0.custom_token_exchange(
    CustomTokenExchangeOptions(
        subject_token="token",
        subject_token_type="urn:acme:mcp-token",
        scope="openid profile email offline_access admin:all"  # Too much
    )
)
```

### 4. HTTPS/TLS

Token exchange MUST occur over HTTPS. The SDK enforces this by:
- Using the Auth0 tenant domain (always HTTPS)
- Validating OIDC metadata endpoints

### 5. Client Authentication

The SDK uses **client_secret_post** authentication method:
- Client credentials are sent in the POST body
- Credentials are protected by TLS encryption
- Never expose `client_secret` in client-side code

---

## Complete Example

Here's a complete FastAPI example integrating custom token exchange:

```python
from fastapi import FastAPI, Request, Response, HTTPException
from starlette.responses import RedirectResponse
from auth0_server_python.auth_server.server_client import ServerClient
from auth0_server_python.auth_types import (
    LoginWithCustomTokenExchangeOptions,
    CustomTokenExchangeOptions
)
from auth0_server_python.error import CustomTokenExchangeError

app = FastAPI()

# Initialize Auth0 client
auth0 = ServerClient(
    domain="your-tenant.auth0.com",
    client_id="your-client-id",
    client_secret="your-client-secret",
    secret="your-encryption-secret"
)

@app.post("/auth/migrate-user")
async def migrate_user(request: Request, response: Response):
    """
    Migrate a user from legacy system to Auth0 using token exchange.
    """
    # Get legacy token from request
    legacy_token = request.headers.get("X-Legacy-Token")
    if not legacy_token:
        raise HTTPException(status_code=400, detail="Missing legacy token")

    try:
        # Exchange legacy token for Auth0 tokens and create session
        result = await auth0.login_with_custom_token_exchange(
            LoginWithCustomTokenExchangeOptions(
                subject_token=legacy_token,
                subject_token_type="urn:company:legacy-token",
                audience="https://api.company.com"
            ),
            store_options={"request": request, "response": response}
        )

        # User is now logged in with Auth0
        user = result.state_data["user"]
        return {
            "status": "success",
            "user_id": user["sub"],
            "message": "User migrated successfully"
        }

    except CustomTokenExchangeError as e:
        raise HTTPException(
            status_code=400,
            detail=f"Token exchange failed: {e.message}"
        )

@app.get("/api/service-call")
async def service_call(request: Request):
    """
    Service-to-service call using actor tokens (delegation).
    """
    # Get user's access token
    user_token = request.headers.get("Authorization", "").replace("Bearer ", "")

    # Get service's access token
    service_token = "<SERVICE_TOKEN>"  # From config/environment

    try:
        # Exchange with delegation
        response = await auth0.custom_token_exchange(
            CustomTokenExchangeOptions(
                subject_token=user_token,
                subject_token_type="urn:ietf:params:oauth:token-type:access_token",
                actor_token=service_token,
                actor_token_type="urn:ietf:params:oauth:token-type:access_token",
                audience="https://downstream-api.company.com"
            )
        )

        # Use delegated token for downstream API call
        return {
            "delegated_token": response.access_token,
            "expires_in": response.expires_in
        }

    except CustomTokenExchangeError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Delegation failed: {e.message}"
        )
```

---

## Additional Resources

- [RFC 8693: OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [Auth0 Documentation](https://auth0.com/docs)
- [Interactive Login Examples](./InteractiveLogin.md)
- [Connected Accounts](./ConnectedAccounts.md)
