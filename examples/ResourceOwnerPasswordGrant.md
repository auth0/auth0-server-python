# Resource Owner Password Grant Examples

> [!WARNING]
> The Resource Owner Password Grant (ROPG) flow should **ONLY** be used by highly-trusted first-party applications where redirect-based flows cannot be used. This flow requires users to expose their credentials directly to the application, which poses significant security risks.
>
> **Always prefer the Authorization Code Flow with PKCE** whenever possible. Only use ROPG when:
> - You control both the client application and the authentication server
> - Redirect-based flows are technically not feasible
> - You fully understand the security implications

## Prerequisites

Before using the Resource Owner Password Grant:

1. Ensure your Auth0 application allows password grants
2. Configure a database connection (e.g., "Username-Password-Authentication")
3. Understand that this flow does NOT support:
   - Multi-factor authentication (MFA)
   - Redirect-based rules
   - Social connections (Google, Facebook, etc.)

## Basic Usage

### Simple Username/Password Authentication

The most basic form of password authentication:

```python
from auth0_server_python.auth_server.server_client import ServerClient
from auth0_server_python.auth_types import TokenByPasswordOptions

# Initialize the Auth0 client
auth0 = ServerClient(
    domain="YOUR_AUTH0_DOMAIN",
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    secret="YOUR_SECRET",
)

async def authenticate_user(username: str, password: str):
    try:
        result = await auth0.get_token_by_password(
            TokenByPasswordOptions(
                username=username,
                password=password
            )
        )

        # Access the authenticated user's information
        user = result["state_data"]["user"]
        print(f"Successfully authenticated: {user['email']}")
        print(f"User ID: {user['sub']}")

        # Access tokens are stored in the state_data
        token_sets = result["state_data"]["token_sets"]
        access_token = token_sets[0]["access_token"]
        print(f"Access token: {access_token[:20]}...")

        return result

    except Exception as e:
        print(f"Authentication failed: {str(e)}")
        return None
```

## Advanced Examples

### Specifying a Realm

When you have multiple database connections, specify which one to authenticate against using the `realm` parameter:

```python
from auth0_server_python.auth_types import TokenByPasswordOptions

async def authenticate_with_realm():
    result = await auth0.get_token_by_password(
        TokenByPasswordOptions(
            username="user@example.com",
            password="secure_password",
            realm="Username-Password-Authentication"  # Specify the database connection
        )
    )

    return result
```

> [!TIP]
> The `realm` parameter is the name of your Auth0 database connection. You can find this in your Auth0 Dashboard under **Authentication → Database**.

### Specifying Audience and Scope

To request access tokens for specific APIs with particular permissions:

```python
from auth0_server_python.auth_types import TokenByPasswordOptions

async def authenticate_with_audience_and_scope():
    result = await auth0.get_token_by_password(
        TokenByPasswordOptions(
            username="user@example.com",
            password="secure_password",
            audience="https://api.example.com",  # Your API identifier
            scope="openid profile email read:posts write:posts offline_access",  # Requested scopes
            realm="Username-Password-Authentication"
        )
    )

    # The access token will be valid for the specified audience
    access_token = result["state_data"]["token_sets"][0]["access_token"]

    # Check if refresh token was issued (requires 'offline_access' scope)
    refresh_token = result["state_data"].get("refresh_token")
    if refresh_token:
        print("Refresh token available for long-term access")

    return result
```

**Common scopes:**
- `openid` - Required for OIDC authentication
- `profile` - Access to user profile information
- `email` - Access to user email
- `offline_access` - Request a refresh token
- Custom scopes - Defined in your Auth0 API settings

### Passing the End-User's IP Address (Server-Side)

When your application acts as an intermediary between end-users and Auth0, forward the end-user's IP address for security and auditing purposes:

```python
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from auth0_server_python.auth_types import TokenByPasswordOptions
from auth0_server_python.error import TokenByPasswordError

app = FastAPI()

class LoginCredentials(BaseModel):
    username: str
    password: str

@app.post("/api/auth/login")
async def login(request: Request, credentials: LoginCredentials):
    """
    Server-side login endpoint that forwards the end-user's IP to Auth0.

    This is important for:
    - Brute force protection
    - Anomaly detection
    - Compliance and auditing
    """
    try:
        # Get the end-user's IP address
        # Note: If behind a proxy, use X-Forwarded-For header instead
        client_ip = request.client.host

        result = await auth0.get_token_by_password(
            TokenByPasswordOptions(
                username=credentials.username,
                password=credentials.password,
                auth0_forwarded_for=client_ip  # Forward the end-user's IP
            )
        )

        return {
            "success": True,
            "user": result["state_data"]["user"],
            "access_token": result["state_data"]["token_sets"][0]["access_token"]
        }

    except TokenByPasswordError as e:
        raise HTTPException(status_code=401, detail=str(e))
```

> [!IMPORTANT]
> **Security Note:** When behind a reverse proxy or load balancer, use the `X-Forwarded-For` header:
> ```python
> client_ip = request.headers.get("X-Forwarded-For", request.client.host)
> ```
> Always validate and sanitize the IP address before forwarding it.

## Error Handling

Handle common authentication errors gracefully:

```python
from auth0_server_python.auth_types import TokenByPasswordOptions
from auth0_server_python.error import (
    TokenByPasswordError,
    MissingRequiredArgumentError,
    ApiError
)

async def authenticate_with_error_handling(username: str, password: str):
    try:
        result = await auth0.get_token_by_password(
            TokenByPasswordOptions(
                username=username,
                password=password
            )
        )
        return {"success": True, "data": result}

    except TokenByPasswordError as e:
        # Handle authentication-specific errors
        error_message = str(e)

        if "Invalid credentials" in error_message:
            return {"success": False, "error": "Wrong username or password"}
        elif "blocked or suspended" in error_message:
            return {"success": False, "error": "Your account has been blocked"}
        elif "MFA" in error_message:
            return {"success": False, "error": "MFA is required. Please use the interactive login flow"}
        elif "Too many authentication attempts" in error_message:
            return {"success": False, "error": "Too many failed attempts. Please try again later"}
        else:
            return {"success": False, "error": "Authentication failed"}

    except MissingRequiredArgumentError as e:
        return {"success": False, "error": f"Missing required field: {e.argument}"}

    except ApiError as e:
        # Handle API/network errors
        return {"success": False, "error": "Authentication service unavailable"}

    except Exception as e:
        # Handle unexpected errors
        return {"success": False, "error": "An unexpected error occurred"}
```

## Complete FastAPI Example

A full working example with FastAPI:

```python
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from auth0_server_python.auth_server.server_client import ServerClient
from auth0_server_python.auth_types import TokenByPasswordOptions
from auth0_server_python.error import TokenByPasswordError

app = FastAPI()

# Initialize Auth0 client
auth0 = ServerClient(
    domain="YOUR_AUTH0_DOMAIN",
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    secret="YOUR_SECRET",
)

class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    remember_me: bool = False

class LoginResponse(BaseModel):
    success: bool
    access_token: str | None = None
    refresh_token: str | None = None
    user: dict | None = None
    error: str | None = None

@app.post("/api/auth/login", response_model=LoginResponse)
async def login(request: Request, credentials: LoginRequest):
    """
    Authenticate a user with email and password.

    This endpoint demonstrates:
    - IP forwarding for security
    - Requesting a refresh token when "remember_me" is enabled
    - Proper error handling
    """
    try:
        # Build authentication options
        options = TokenByPasswordOptions(
            username=credentials.email,
            password=credentials.password,
            scope="openid profile email" + (" offline_access" if credentials.remember_me else ""),
            auth0_forwarded_for=request.client.host
        )

        # Authenticate
        result = await auth0.get_token_by_password(options)

        # Extract tokens and user info
        user_data = result["state_data"]["user"]
        token_set = result["state_data"]["token_sets"][0]
        refresh_token = result["state_data"].get("refresh_token")

        return LoginResponse(
            success=True,
            access_token=token_set["access_token"],
            refresh_token=refresh_token,
            user={
                "id": user_data["sub"],
                "email": user_data.get("email"),
                "name": user_data.get("name")
            }
        )

    except TokenByPasswordError as e:
        return LoginResponse(
            success=False,
            error=str(e)
        )

    except Exception as e:
        return LoginResponse(
            success=False,
            error="Authentication failed due to an unexpected error"
        )

@app.get("/api/auth/user")
async def get_current_user():
    """
    Retrieve the currently authenticated user from the session.

    After successful password authentication, the user session is stored
    and can be retrieved with this method.
    """
    user = await auth0.get_user()
    if user:
        return {"user": user}
    else:
        raise HTTPException(status_code=401, detail="Not authenticated")
```

## Security Best Practices

### 1. Always Use HTTPS

ROPG transmits credentials over the network. Always use HTTPS in production:

```python
# In production, ensure your application only accepts HTTPS
if not request.url.scheme == "https":
    raise HTTPException(status_code=400, detail="HTTPS required")
```

### 2. Implement Rate Limiting

Protect against brute force attacks:

```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@app.post("/api/auth/login")
@limiter.limit("5/minute")  # Max 5 attempts per minute
async def login(request: Request, credentials: LoginRequest):
    # ... authentication logic
    pass
```

### 3. Log Authentication Attempts

Log all authentication attempts for security auditing:

```python
import logging

logger = logging.getLogger(__name__)

async def authenticate_with_logging(username: str):
    try:
        result = await auth0.get_token_by_password(...)
        logger.info(f"Successful login for user: {username}")
        return result
    except TokenByPasswordError as e:
        logger.warning(f"Failed login attempt for user: {username} - {str(e)}")
        raise
```

### 4. Never Log Passwords

Never log, store, or transmit passwords in plaintext:

```python
# NEVER DO THIS
logger.info(f"Login attempt: {username}:{password}")  # ❌ BAD

# DO THIS INSTEAD
logger.info(f"Login attempt for user: {username}")  # ✅ GOOD
```

## Common Issues and Solutions

### Issue: MFA Required Error

**Problem:** User has MFA enabled, but ROPG doesn't support MFA.

**Solution:** Direct the user to use the interactive login flow:

```python
try:
    result = await auth0.get_token_by_password(...)
except TokenByPasswordError as e:
    if "MFA" in str(e):
        return {
            "error": "mfa_required",
            "message": "Please use the web login for multi-factor authentication",
            "login_url": "https://your-app.com/login"
        }
```

### Issue: Invalid Realm

**Problem:** Specified realm doesn't exist or isn't configured for password grants.

**Solution:** Verify the realm name matches your Auth0 database connection:

```python
# Check your Auth0 Dashboard: Authentication → Database
realm = "Username-Password-Authentication"  # Use exact name from dashboard
```

### Issue: Account Blocked

**Problem:** Too many failed login attempts have blocked the account.

**Solution:** Inform the user and provide account recovery options:

```python
if "blocked or suspended" in str(error):
    return {
        "error": "account_blocked",
        "message": "Your account has been temporarily blocked due to multiple failed login attempts.",
        "recovery_url": "https://your-app.com/account/recovery"
    }
```

## Migration from Other Flows

If you're currently using ROPG and want to migrate to Authorization Code Flow with PKCE:

```python
# OLD: Resource Owner Password Grant
result = await auth0.get_token_by_password(
    TokenByPasswordOptions(username=username, password=password)
)

# NEW: Interactive Login (Recommended)
# 1. Redirect user to authorization URL
auth_url = await auth0.start_interactive_login()
return RedirectResponse(url=auth_url)

# 2. Handle callback
result = await auth0.complete_interactive_login(callback_url)
```

## Additional Resources

- [Auth0 Documentation: Resource Owner Password Flow](https://auth0.com/docs/get-started/authentication-and-authorization-flow/resource-owner-password-flow)
- [OAuth 2.0 RFC 6749 Section 4.3](https://tools.ietf.org/html/rfc6749#section-4.3)
- [Auth0 Security Best Practices](https://auth0.com/docs/security)
- [Interactive Login Examples](./InteractiveLogin.md) (Recommended alternative)
