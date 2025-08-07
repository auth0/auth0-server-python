# Auth0 API Python Examples

This document provides examples for using the `auth0-api-python` package to validate Auth0 tokens in your API.

## Bearer Authentication

Bearer authentication is the standard OAuth 2.0 token authentication method.

### Using verify_access_token

```python
import asyncio
from auth0_api_python import ApiClient, ApiClientOptions

async def validate_bearer_token(headers):
    api_client = ApiClient(ApiClientOptions(
        domain="your-tenant.auth0.com",
        audience="https://api.example.com"
    ))
    
    try:
        # Extract the token from the Authorization header
        auth_header = headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            return {"error": "Missing or invalid authorization header"}, 401
            
        token = auth_header.split(" ")[1]
        
        # Verify the access token
        claims = await api_client.verify_access_token(token)
        return {"success": True, "user": claims["sub"]}
    except Exception as e:
        return {"error": str(e)}, getattr(e, "get_status_code", lambda: 401)()

# Example usage
headers = {"authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."}
result = asyncio.run(validate_bearer_token(headers))
```

### Using verify_request

```python
import asyncio
from auth0_api_python import ApiClient, ApiClientOptions
from auth0_api_python.errors import BaseAuthError

async def validate_request(headers):
    api_client = ApiClient(ApiClientOptions(
        domain="your-tenant.auth0.com",
        audience="https://api.example.com"
    ))
    
    try:
        # Verify the request with Bearer token
        claims = await api_client.verify_request(
            headers=headers
        )
        return {"success": True, "user": claims["sub"]}
    except BaseAuthError as e:
        return {"error": str(e)}, e.get_status_code(), e.get_headers()

# Example usage
headers = {"authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."}
result = asyncio.run(validate_request(headers))
```


## DPoP Authentication 

[DPoP](https://www.rfc-editor.org/rfc/rfc9449.html) (Demonstrating Proof of Posession) is an application-level mechanism for sender-constraining OAuth 2.0 access and refresh tokens by proving that the client application is in possession of a certain private key.

This guide covers the DPoP implementation in `auth0-api-python` with complete examples for both operational modes.

For more information about DPoP specification, see [RFC 9449](https://tools.ietf.org/html/rfc9449).

## Configuration Modes

### 1. Allowed Mode (Default)
```python
from auth0_api_python import ApiClient, ApiClientOptions

api_client = ApiClient(ApiClientOptions(
    domain="your-tenant.auth0.com",
    audience="https://api.example.com",
    dpop_enabled=True,      # Default: enables DPoP support
    dpop_required=False     # Default: allows both Bearer and DPoP
))
```

### 2. Required Mode
```python
api_client = ApiClient(ApiClientOptions(
    domain="your-tenant.auth0.com",
    audience="https://api.example.com",
    dpop_required=True      # Enforces DPoP-only authentication
))
```

## Getting Started

### Basic Usage with verify_request()

The `verify_request()` method automatically detects the authentication scheme:

```python
import asyncio
from auth0_api_python import ApiClient, ApiClientOptions

async def handle_api_request(headers, http_method, http_url):
    api_client = ApiClient(ApiClientOptions(
        domain="your-tenant.auth0.com",
        audience="https://api.example.com"
    ))
    
    try:
        # Automatically handles both Bearer and DPoP schemes
        claims = await api_client.verify_request(
            headers=headers,
            http_method=http_method,
            http_url=http_url
        )
        return {"success": True, "user": claims["sub"]}
    except Exception as e:
        return {"error": str(e)}, e.get_status_code()

# Example usage
headers = {
    "authorization": "DPoP eyJ0eXAiOiJKV1Q...",
    "dpop": "eyJ0eXAiOiJkcG9wK2p3dC..."
}
result = asyncio.run(handle_api_request(headers, "GET", "https://api.example.com/data"))
```

### Direct DPoP Proof Verification

For more control, use `verify_dpop_proof()` directly:

```python
async def verify_dpop_token(access_token, dpop_proof, http_method, http_url):
    api_client = ApiClient(ApiClientOptions(
        domain="your-tenant.auth0.com",
        audience="https://api.example.com"
    ))
    
    # First verify the access token
    token_claims = await api_client.verify_access_token(access_token)
    
    # Then verify the DPoP proof
    proof_claims = await api_client.verify_dpop_proof(
        access_token=access_token,
        proof=dpop_proof,
        http_method=http_method,
        http_url=http_url
    )
    
    return {
        "token_claims": token_claims,
        "proof_claims": proof_claims
    }
```