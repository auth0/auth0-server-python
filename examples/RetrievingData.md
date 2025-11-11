# Retrieving Data

## Retrieving the logged-in User

The SDK's `get_user()` can be used to retrieve the current logged-in user:

```python
user = await serverClient.get_user();
```

### Passing Store Options

Just like most methods, `getUser` accept an argument that is used to pass to the configured Transaction and State Store:

```python
store_options = {
    # e.g. "request": <some_request_object>,
    #      "response": <some_response_object>
}
user = await server_client.get_user(store_options=store_options)
```

Read more above in [Configuring the Store](./ConfigureStore.md).

## Retrieving the Session Data

The SDK's `get_session()` can be used to retrieve the current session data:

```python
session = await serverClient.get_session();
```

### Passing Store Options

Just like most methods, `get_session` accept an argument that is used to pass to the configured Transaction and State Store:

```python
store_options = {
    # e.g. "request": <some_request_object>,
    #      "response": <some_response_object>
}
session = await server_client.get_session(store_options=store_options)
```

Read more above in [Configuring the Store](./ConfigureStore.md).

## Retrieving an Access Token

The SDK's `get_access_token()` can be used to retrieve an Access Token for the current logged-in user:

```python
access_token = await server_client.get_access_token()
```

The SDK will cache the token internally, and return it from the cache when not expired. When no token is found in the cache, or the token is expired, calling `get_access_token()` will call Auth0 to retrieve a new token and update the cache.

In order to do this, the SDK needs access to a Refresh Token. By default, the SDK is configured to request the `offline_access` scope. If you override the scopes, ensure to always include `offline_access` if you want to be able to retrieve and refresh an access token.

### Passing Store Options

Just like most methods, `getAccessToken` accept an argument that is used to pass to the configured Transaction and State Store:

```python
store_options = {
    # e.g. "request": <some_request_object>,
    #      "response": <some_response_object>
}
access_token = await server_client.get_access_token(store_options=store_options)
```

Read more above in [Configuring the Store](./ConfigureStore.md).

## Multi-Resource Refresh Tokens (MRRT)

Multi-Resource Refresh Tokens allow using a single refresh token to obtain access tokens for multiple audiences, simplifying token management in applications that interact with multiple backend services.

Read more about [Multi-Resource Refresh Tokens in the Auth0 documentation](https://auth0.com/docs/secure/tokens/refresh-tokens/multi-resource-refresh-token).


> [!WARNING]
> When using Multi-Resource Refresh Token Configuration (MRRT), **Refresh Token Policies** on your Application need to be configured with the audiences you want to support. See the [Auth0 MRRT documentation](https://auth0.com/docs/secure/tokens/refresh-tokens/multi-resource-refresh-token) for setup instructions.
>
> **Tokens requested for audiences outside your configured policies will be ignored by Auth0, which will return a token for the default audience instead!**

### Configuring Scopes Per Audience

When working with multiple APIs, you can define different default scopes for each audience by passing an object instead of a string. This is particularly useful when different APIs require different default scopes:

```python
server_client = ServerClient(
    ...
    authorization_params={
        "audience": "https://api.example.com", # Default audience
        scope: {
            "https://api.example.com": "openid profile email offline_access read:products read:orders",
            "https://analytics.example.com": "openid profile email offline_access read:analytics write:analytics",
            "https://admin.example.com": "openid profile email offline_access read:admin write:admin delete:admin"
        }
    }
)
```

**How it works:**

- Each key in the `scope` object is an `audience` identifier
- The corresponding value is the scope string for that audience
- When calling `get_access_token(audience=audience)`, the SDK automatically uses the configured scopes for that audience. When scopes are also passed in the method call, they are be merged with the default scopes for that audience.

### Usage Example

To retrieve access tokens for different audiences, use the `get_access_token()` method with an `audience` (and optionally also the `scope`) parameter.

```python

server_client = ServerClient(
    ...
    authorization_params={
        "audience": "https://api.example.com", # Default audience
        "scope": {
            "https://api.example.com": "openid email profile",
            "https://analytics.example.com": "read:analytics write:analytics"
        }
    }
)

# Get token for default audience
default_token = await server_client.get_access_token()
# returns token for https://api.example.com with openid, email, and profile scopes

 # Get token for different audience
data_token = await server_client.get_access_token(audience="https://data-api.example.com")
# returns token for https://analytics.example.com with read:analytics and write:analytics scopes

# Get token with additional scopes
admin_token = await server_client.get_access_token(
    audience="https://api.example.com",
    scope="write:admin"
)
# returns token for https://api.example.com with openid, email, profile and write:admin scopes

```

### Token Management Best Practices

**Configure Broad Default Scopes**: Define comprehensive scopes in your `ServerClient` constructor for common use cases. This minimizes the need to request additional scopes dynamically, reducing the amount of tokens that need to be stored.

```python
server_client = ServerClient(
    ...
    authorization_params={
        "audience": "https://api.example.com", # Default audience
        # Configure broad default scopes for most common operations
        "scope": {
            "https://api.example.com": "openid profile email offline_access read:products read:orders read:users"
        }
    }
)
```

**Minimize Dynamic Scope Requests**: Avoid passing `scope` when calling `get_access_token()` unless absolutely necessary. Each `audience` + `scope` combination results in a token to store in the session, increasing session size.

```python
# Preferred: Use default scopes
token = await server_client.get_access_token(audience="https://api.example.com")


# Avoid unless necessary: Dynamic scopes increase session size
token = await server_client.get_access_token(
    audience="https://api.example.com"
    scope="openid profile email read:products write:products admin:all"
)
```

## Retrieving an Access Token for a Connections

The SDK's `get_access_token_for_connection()` can be used to retrieve an Access Token for a connection (e.g. `google-oauth2`) for the current logged-in user:

```python
connection_options = {
    "connection": "google-oauth2"
    # optionally "login_hint": "<some_hints>"
}
access_token_for_google = await server_client.get_access_token_for_connection(connection_options)

```

- `connection`: The connection for which an access token should be retrieved, e.g. `google-oauth2` for Google.
- `loginHint`: Optional login hint to inform which connection account to use, can be useful when multiple accounts for the connection exist for the same user. 

The SDK will cache the token internally, and return it from the cache when not expired. When no token is found in the cache, or the token is expired, calling `get_access_token_for_connection()` will call Auth0 to retrieve a new token and update the cache.

In order to do this, the SDK needs access to a Refresh Token. So ensure to always include `offline_access` if you want to be able to retrieve and refresh an access token for a connection.

### Passing Store Options 

Just like most methods, `get_access_token_for_connection()` accepts a second argument that is used to pass to the configured Transaction and State Store:

```python
store_options = {
    # e.g. "request": <some_request_object>,
    #      "response": <some_response_object>
}
access_token_for_google = await server_client.get_access_token_for_connection(connection_options, store_options=store_options)
```

Read more above in [Configuring the Store](./ConfigureStore.md).

