The Auth0 FastAPI API SDK library allows you to secure FastAPI APIs using bearer tokens from Auth0.

It exposes a simple require_auth dependency that checks if incoming requests have a valid JWT, then provides the token claims to your route handler.

![Release](https://img.shields.io/pypi/v/auth0-fastapi-api) ![Downloads](https://img.shields.io/pypi/dw/auth0-fastapi-api) [![License](https://img.shields.io/:license-MIT-blue.svg?style=flat)](https://opensource.org/licenses/MIT)

📚 [Documentation](#documentation) - 🚀 [Getting Started](#getting-started) - 💬 [Feedback](#feedback)

## Documentation

- [QuickStart](https://auth0.com/docs/quickstart/webapp/fastapi)- our guide for adding Auth0 to your Fastapi app.
- [Examples](https://github.com/auth0/auth0-server-python/blob/main/packages/auth0_server_python/EXAMPLES.md) - examples for your different use cases.
- [Docs Site](https://auth0.com/docs) - explore our docs site and learn more about Auth0.

## Getting Started

### 1. Install the SDK

_This library requires Python 3.9+._

```shell
pip install auth0-fastapi-api
```

If you’re using Poetry:

```shell
poetry install auth0-fastapi-api
```

### 2. Configure and Register the Auth0FastAPI Plugin

In your FastAPI application, create an instance of the `Auth0FastAPI` class. Supply the `domain` and `audience` from Auth0:
- The `AUTH0_DOMAIN` can be obtained from the [Auth0 Dashboard](https://manage.auth0.com) once you've created an API. 
- The `AUTH0_AUDIENCE` is the identifier of the API that is being called. You can find this in the API section of the Auth0 dashboard.

```python
from auth0_fastapi_api import Auth0FastAPI

# Create the Auth0 integration
auth0 = Auth0FastAPI(
    domain="<AUTH0_DOMAIN>",
    audience="<AUTH0_AUDIENCE>",
)
```

### 3. Protecting API Routes

To protect a FastAPI route, use the `require_auth(...)` dependency. Any incoming requests must include a valid Bearer token (JWT) in the `Authorization` header, or they will receive an error response (e.g., 401 Unauthorized).

```python
@app.get("/protected-api")
async def protected(
    # The route depends on require_auth returning the decoded token claims
    claims: dict = Depends(auth0.require_auth())
):
    # `claims` is the verified JWT payload (dict) extracted by the SDK
    return {"message": f"Hello, {claims['sub']}"}
```

#### How It Works

1. The user sends a request with `Authorization: Bearer <JWT>`.
2. The SDK parses the token, checks signature via Auth0’s JWKS, validates standard claims like `iss`, `aud`, `exp`, etc.
3. If valid, the route receives the decoded claims as a Python dict (e.g. `{"sub": "user123", "scope": "read:stuff", ...}`).

> [!IMPORTANT]  
> This method protects API endpoints using bearer tokens. It does not **create or manage user sessions in server-side rendering scenarios**. For session-based usage, consider a separate library or approach.

#### Custom Claims
If your tokens have **additional** custom claims, you’ll see them in the `claims` dictionary. For example:
```python
@app.get("/custom")
async def custom_claims_route(claims: dict = Depends(auth0.require_auth())):
    # Suppose your JWT includes { "permissions": ["read:data"] }
    permissions = claims.get("permissions", [])
    return {"permissions": permissions}

```
You can parse or validate these claims however you like in your application code.

### 4. Advanced Configuration
- **Scopes**: If you need to check for specific scopes (like `read:data`), call r`equire_auth(scopes="read:data")` or pass a list of scopes. The SDK will return a 403 if the token lacks those scopes in its `scope` claim.
```python
@app.get("/read-data")
async def read_data_route(
    claims=Depends(auth0.require_auth(scopes="read:data"))
):
    return {"data": "secret info"}
```
- **Mocking / Testing**: To test locally without hitting Auth0’s actual JWKS endpoints, you can mock the HTTP calls using `pytest-httpx` or patch the verification method to avoid real cryptographic checks.

<details>
<summary> Example</summary>

```python
from fastapi import FastAPI, Depends
from auth0_fastapi_api import Auth0FastAPI
from fastapi.testclient import TestClient

app = FastAPI()
auth0 = Auth0FastAPI(domain="my-tenant.us.auth0.com", audience="my-api")

@app.get("/public")
async def public():
    return {"message": "No token required here"}

@app.get("/secure")
async def secure_route(
    claims: dict = Depends(auth0.require_auth(scopes="read:secure"))
):
    # claims might contain {"sub":"user123","scope":"read:secure"}
    return {"message": f"Hello {claims['sub']}, you have read:secure scope!"}

# Example test
def test_public_route():
    client = TestClient(app)
    response = client.get("/public")
    assert response.status_code == 200
    assert response.json() == {"message": "No token required here"}
```

</details>

## Feedback

### Contributing

We appreciate feedback and contribution to this repo! Before you get started, please read the following:

- [Auth0's general contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)
- [Auth0's code of conduct guidelines](https://github.com/auth0/open-source-template/blob/master/CODE-OF-CONDUCT.md)
- [This repo's contribution guide](./../../CONTRIBUTING.md)

### Raise an issue

To provide feedback or report a bug, please [raise an issue on our issue tracker](https://github.com/auth0/auth0-fastapi-api/issues).

## Vulnerability Reporting

Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/responsible-disclosure-policy) details the procedure for disclosing security issues.

## What is Auth0?

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_dark_mode.png" width="150">
    <source media="(prefers-color-scheme: light)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png" width="150">
    <img alt="Auth0 Logo" src="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png" width="150">
  </picture>
</p>
<p align="center">
  Auth0 is an easy to implement, adaptable authentication and authorization platform. To learn more checkout <a href="https://auth0.com/why-auth0">Why Auth0?</a>
</p>
<p align="center">
  This project is licensed under the MIT license. See the <a href="https://github.com/auth0/auth0-server-python/blob/main/packages/auth0_fastapi_api/LICENSE"> LICENSE</a> file for more info.
</p>