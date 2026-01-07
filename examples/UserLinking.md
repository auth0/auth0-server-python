## Start Linking The User

User‑linking begins with configuring a `redirect_uri`—the URL Auth0 will use to redirect the user after authentication—and then calling `start_link_user()` to obtain an authorization URL.

```python
# Instantiate the core server client with global authorization parameters.
server_client = ServerClient(
    domain="YOUR_AUTH0_DOMAIN",
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    secret="YOUR_SECRET",
    authorization_params={
        "audience": "urn:custom:api",
        "redirect_uri"="http://localhost:3000/auth/callback",
        "scope": "your-scopes"
    }
)

# Start the link user flow by providing options programmatically.
options = {
    "connection": "connection-name",
    "connection_scope": "connection-scope",
    "authorization_params": {"redirect_uri": "http://localhost:3000/auth/callback"},
    "app_state": {"returnTo": "http://localhost:3000"}
}

# Assume store_options contains Request/Response objects required by the state store.
store_options = {"request": DummyRequest(), "response": DummyResponse()}

link_user_url = await server_client.start_link_user(options, store_options=store_options)

# Redirect the user to link_user_url
# (In a FastAPI route, you would return a RedirectResponse with link_user_url)

```

Once the link user flow is completed, the user will be redirected back to the `redirect_uri` specified in the `authorization_params`. At that point, it's required to call `complete_link_user()` to finalize the user-linking process. Read more below in [Complete Linking The User](#complete-linking-the-user).

### Passing `authorization_params`

You can customize the parameters passed to the /authorize endpoint in two ways:

1. **Globally:**
    Configure them when instantiating the ServerClient:
    ```python
    server_client = ServerClient(
        domain="YOUR_AUTH0_DOMAIN",
        client_id="YOUR_CLIENT_ID",
        client_secret="YOUR_CLIENT_SECRET",
        secret="YOUR_SECRET",
        authorization_params={
            "redirect_uri": "http://localhost:3000/auth/callback"
            "audience": "urn:custom:api",
            "scope": "openid profile email offline_access"
        }
    )
    ```

2. **Per-call Override:**
    Supply them when calling `start_link_user()`.


    ```python
    options = {
        "authorization_params": {
            "audience": "urn:another:api",
            "foo": "bar"
        }
    }
    link_user_url = await server_client.start_link_user(options, store_options=store_options)
    });
    ```
>[!NOTE]
> Keep in mind that, any `authorization_params` property specified when calling `start_link_user`, will override the same, statically configured, `authorization_params` property on `ServerClient`.


### Passing App State to track state during login

The `app_state` parameter allows you to pass custom data (for example, a returnTo URL) that will be returned when the linking process is complete.

```python
options = {
    "app_state": {"return_to": "http://localhost:3000/dashboard"}
}
link_user_url = await server_client.start_link_user(options, store_options=store_options)
# Later, when completing linking:
result = await server_client.complete_link_user(callback_url, store_options=store_options)
print(result.get("app_state").get("return_to"))  # Should output "http://localhost:3000/dashboard"

```

> [!TIP]
> Using `app_state` can be useful for a variaty of reasons, but is mostly supported to enable using a `return_to` parameter in framework-specific SDKs that use this SDK.

### Passing Store Options
Every method that interacts with the state or transaction store accepts a second parameter, `store_options`. This parameter should include the HTTP request and response objects (or equivalents) needed to manage cookies or sessions.

```python
store_options = {"request": request, "response": response}
link_user_url = await server_client.start_link_user(options, store_options=store_options)

```

Read more above in [Configuring the Transaction and State Store](./ConfigureStore.md).

## Complete Linking The User

After the user has been redirected back to your application (at the `redirect_uri`), you need to complete the linking process. This is done by calling `complete_link_user()`, which extracts the necessary parameters from the callback URL and returns the `app_state`.

```python
# Complete the linking process:
result = await server_client.complete_link_user(callback_url, store_options=store_options)
# Retrieve the appState:
print(result.get("appState").get("return_to"))
```

> [!NOTE]
> TThe URL passed to `complete_link_user()` should be the full callback URL from Auth0, including the `state` and `code` parameters.


### Passing Store Options
Just like most methods, `complete_link_user()` accept a second argument that is used to pass to the configured Transaction and State Store:

```python
store_options = {"request": request, "response": response}
link_user_url = await server_client.start_link_user(options, store_options=store_options)
```

Read more above in [Configuring the Transaction and State Store](./ConfigureStore.md).

## Start Unlinking The User

User unlinking allows you to remove a previously linked identity from a user account. The process is similar to linking and begins by calling `start_unlink_user()` to obtain an authorization URL.

```python
# Start the unlink user flow by providing the connection to unlink.
options = {
    "connection": "google-oauth2",  # The connection to unlink
    "authorization_params": {"redirect_uri": "http://localhost:3000/auth/callback"},
    "app_state": {"returnTo": "http://localhost:3000/profile"}
}

# Assume store_options contains Request/Response objects required by the state store.
store_options = {"request": request, "response": response}

unlink_user_url = await server_client.start_unlink_user(options, store_options=store_options)

# Redirect the user to unlink_user_url
# (In a FastAPI route, you would return a RedirectResponse with unlink_user_url)
```

Once the unlink user flow is completed, the user will be redirected back to the `redirect_uri` specified in the `authorization_params`. At that point, it's required to call `complete_unlink_user()` to finalize the user-unlinking process. Read more below in [Complete Unlinking The User](#complete-unlinking-the-user).

### Passing `authorization_params`

Just like `start_link_user()`, you can customize the parameters passed to the `/authorize` endpoint:

1. **Globally:**
    Configure them when instantiating the `ServerClient`.

2. **Per-call Override:**
    Supply them when calling `start_unlink_user()`.

```python
options = {
    "connection": "google-oauth2",
    "authorization_params": {
        "redirect_uri": "http://localhost:3000/auth/callback",
        "audience": "urn:custom:api"
    }
}
unlink_user_url = await server_client.start_unlink_user(options, store_options=store_options)
```

>[!NOTE]
> Any `authorization_params` property specified when calling `start_unlink_user()` will override the same, statically configured, `authorization_params` property on `ServerClient`.

### Passing App State

The `app_state` parameter allows you to pass custom data (for example, a return URL) that will be returned when the unlinking process is complete.

```python
options = {
    "connection": "google-oauth2",
    "app_state": {"return_to": "http://localhost:3000/profile"}
}
unlink_user_url = await server_client.start_unlink_user(options, store_options=store_options)

# Later, when completing unlinking:
result = await server_client.complete_unlink_user(callback_url, store_options=store_options)
print(result.get("app_state").get("return_to"))  # Should output "http://localhost:3000/profile"
```

### Passing Store Options

Every method that interacts with the state or transaction store accepts a second parameter, `store_options`. This parameter should include the HTTP request and response objects (or equivalents) needed to manage cookies or sessions.

```python
store_options = {"request": request, "response": response}
unlink_user_url = await server_client.start_unlink_user(options, store_options=store_options)
```

Read more above in [Configuring the Transaction and State Store](./ConfigureStore.md).

## Complete Unlinking The User

After the user has been redirected back to your application (at the `redirect_uri`), you need to complete the unlinking process. This is done by calling `complete_unlink_user()`, which extracts the necessary parameters from the callback URL and returns the `app_state`.

```python
# Complete the unlinking process:
result = await server_client.complete_unlink_user(callback_url, store_options=store_options)

# Retrieve the app_state:
print(result.get("app_state").get("return_to"))
```

> [!NOTE]
> The URL passed to `complete_unlink_user()` should be the full callback URL from Auth0, including the `state` and `code` parameters.

### Passing Store Options

Just like most methods, `complete_unlink_user()` accepts a second argument that is used to pass to the configured Transaction and State Store:

```python
store_options = {"request": request, "response": response}
result = await server_client.complete_unlink_user(callback_url, store_options=store_options)
```

Read more above in [Configuring the Transaction and State Store](./ConfigureStore.md).
