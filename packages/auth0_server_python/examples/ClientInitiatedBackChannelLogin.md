# Backchannel Authentication Examples

Client-Initiated Backchannel Authentication (CIBA) enables applications to authenticate users via a separate channel or device, without requiring browser-based redirects. This is especially useful for IoT devices, call center authentication, and scenarios where the authentication device is different from the requesting device.

## Prerequisites

Before using backchannel authentication:

1. Enable CIBA in your Auth0 dashboard (Authentication → Flows → Client-Initiated Backchannel Authentication)
2. Ensure you have the proper scopes configured for your application
3. Set up your Auth0 SDK with the required credentials

## Basic Usage

### Initiating Backchannel Authentication

```python
from auth0_server_python import ServerClient

# Initialize the Auth0 client
auth0 = ServerClient(
    domain="YOUR_AUTH0_DOMAIN",
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    secret="YOUR_SECRET",
)

async def authenticate_via_backchannel():
    # Configure backchannel options
    options = {
        "login_hint": {"sub": "user-id"},  # The user identifier
        "binding_message": "Login to Example App"  # Message displayed to the user
    }
    
    # Initiate backchannel authentication
    try:
        result = await auth0.login_backchannel(options)
        
        # Authentication successful
        print(f"User authenticated successfully")
        print(f"Token type: {result.get('token_type')}")
        print(f"Expires in: {result.get('expires_in')} seconds")
        
        # You can now use the session for API calls
        return result
    except Exception as e:
        print(f"Authentication failed: {str(e)}")
        return None
```

- `binding_message`: An optional, human-readable message to be displayed at the consumption device and authentication device. This allows the user to ensure the transaction initiated by the consumption device is the same that triggers the action on the authentication device.
- `login_hint['sub']`: The `sub` claim of the user that is trying to login using Client-Initiated Backchannel Authentication, and to which a push notification to authorize the login will be sent.

> [!IMPORTANT]
> - Using Client-Initiated Backchannel Authentication requires the feature to be enabled in the Auth0 dashboard.
> - Read [the Auth0 docs](https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-initiated-backchannel-authentication-flow) to learn more about Client-Initiated Backchannel Authentication.

### Using Rich Authorization Requests
When using Client-Initiated Backchannel Authentication, you can also use Rich Authorization Requests (RAR) by setting `authorizationParams.authorization_details`:


```python

result = await auth0.login_backchannel({
    "binding_message": "<binding_message>",
    "login_hint": {
        "sub": "auth0|123456789"
    },
    "authorization_params": {
        "authorization_details": json.dumps([{
            "type": "<type>",
            # additional fields here
        }])
    }
})
```

> [!IMPORTANT]
> - Audience must be explicitly specified when `authorization_details` parameter is passed
> - Using Client-Initiated Backchannel Authentication with Rich Authorization Requests (RAR) requires the feature to be enabled in the Auth0 dashboard.
> - Read [the Auth0 docs](https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-initiated-backchannel-authentication-flow) to learn more about Client-Initiated Backchannel Authentication.

### Passing Store Options

Just like most methods, `login_backchannel()` accept a second argument that is used to pass to the configured Transaction and State Store:

```python
store_options = { /* ... */ }
await auth0.login_backchannel({}, store_options)
```

Read more above in [Configuring the Store](./ConfigureStore.md).

### Example (FastAPI)

```python

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from auth0_server_python import ServerClient

app = FastAPI()

# Initialize Auth0 client
auth0 = ServerClient(
    domain="YOUR_AUTH0_DOMAIN",
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    secret="YOUR_SECRET",
)

@app.post("/api/auth/backchannel")
async def backchannel_login(request: Request):
    try:
        result = await auth0.login_backchannel({
            "binding_message": "Login to Example App",
            "login_hint": {
                "sub": "auth0|123456789"
            }
        })
        
        # Successfully authenticated
        return JSONResponse(content={
            "status": "success",
            "message": "User authenticated via backchannel"
        })
    except Exception as e:
        return JSONResponse(content={
            "status": "error",
            "message": str(e)
        })
```