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

Enable delegation scenarios where one service acts on behalf of a user.

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
```

## 4. Custom Authorization Parameters

Pass additional parameters to the token endpoint.

```python
response = await auth0.custom_token_exchange(
    CustomTokenExchangeOptions(
        subject_token="custom-token",
        subject_token_type="urn:acme:mcp-token",
        audience="https://api.example.com",
        authorization_params={
            "organization": "org_123",
            "custom_field": "custom_value"
        }
    )
)
```

> **NOTE**: Critical parameters (`grant_type`, `client_id`, `subject_token`, `subject_token_type`) cannot be overridden via `authorization_params` for security reasons.

## 5. Error Handling

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
- `TOKEN_EXCHANGE_FAILED`: General token exchange failure
- `INVALID_RESPONSE`: Auth0 returned a non-JSON response

## 6. Token Type URIs

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

## Additional Resources

- [Auth0 Custom Token Exchange Documentation](https://auth0.com/docs/authenticate/custom-token-exchange)
- [RFC 8693 - OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
