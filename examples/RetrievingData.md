# Retrieving Data

## Retrieving the logged-in User

The SDK's `get_user()` can be used to retrieve the current logged-in user:

```python
user = await serverClient.get_user();
```

### Passing `StoreOptions`

Just like most methods, `getUser` accept an argument that is used to pass to the configured Transaction and State Store:

```python
store_options = {
    # e.g. "request": <some_request_object>,
    #      "response": <some_response_object>
}
user = await server_client.get_user(store_options=store_options)
```

Read more above in [Configuring the Store](#configuring-the-store)

## Retrieving the Session Data

The SDK's `get_session()` can be used to retrieve the current session data:

```python
session = await serverClient.get_session();
```

### Passing `StoreOptions`

Just like most methods, `get_session` accept an argument that is used to pass to the configured Transaction and State Store:

```python
store_options = {
    # e.g. "request": <some_request_object>,
    #      "response": <some_response_object>
}
session = await server_client.get_session(store_options=store_options)
```

Read more above in [Configuring the Store](#configuring-the-store)

## Retrieving an Access Token

The SDK's `getAccessToken()` can be used to retrieve an Access Token for the current logged-in user:

```python
access_token = await server_client.get_access_token()
```

The SDK will cache the token internally, and return it from the cache when not expired. When no token is found in the cache, or the token is expired, calling `getAccessToken()` will call Auth0 to retrieve a new token and update the cache.

In order to do this, the SDK needs access to a Refresh Token. By default, the SDK is configured to request the `offline_access` scope. If you override the scopes, ensure to always include `offline_access` if you want to be able to retrieve and refresh an access token.

### Passing `StoreOptions`

Just like most methods, `getAccessToken` accept an argument that is used to pass to the configured Transaction and State Store:

```python
store_options = {
    # e.g. "request": <some_request_object>,
    #      "response": <some_response_object>
}
access_token = await server_client.get_access_token(store_options=store_options)
```

Read more above in [Configuring the Store](#configuring-the-store)

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

In order to do this, the SDK needs access to a Refresh Token. By default, the SDK is configured to request the `offline_access` scope. If you override the scopes, ensure to always include `offline_access` if you want to be able to retrieve and refresh an access token for a connection.

### Passing `StoreOptions`

Just like most methods, `get_access_token_for_connection()` accepts a second argument that is used to pass to the configured Transaction and State Store:

```python
store_options = {
    # e.g. "request": <some_request_object>,
    #      "response": <some_response_object>
}
access_token_for_google = await server_client.get_access_token_for_connection(connection_options, store_options=store_options)
```

Read more above in [Configuring the Store](#configuring-the-store)
