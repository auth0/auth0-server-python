## Start Linking The User

User‑linking begins with configuring a `redirect_uri`—the URL Auth0 will use to redirect the user after authentication—and then calling `start_link_user()` to obtain an authorization URL.

```python
# Instantiate the core server client with global authorization parameters.
server_client = ServerClient(
    domain="your-domain.auth0.com",
    client_id="your-client-id",
    client_secret="your-client-secret",
    secret="your-encryption-secret"
    authorization_params={
        "audience": "urn:custom:api",
        "redirect_uri"="http://localhost:3000/auth/callback",
        "scope": "your-scopes"
    }
)

# Start the link user flow by providing options programmatically.
options = {
    "connection": "connection-name",
    "connectionScope": "connection-scope",
    "authorization_params": {"redirect_uri": "http://localhost:3000/auth/callback"},
    "appState": {"returnTo": "http://localhost:3000"}
}

# Assume store_options contains Request/Response objects required by the state store.
store_options = {"request": DummyRequest(), "response": DummyResponse()}

link_user_url = await server_client.start_link_user(options, store_options=store_options)

# Redirect the user to link_user_url
# (In a FastAPI route, you would return a RedirectResponse with link_user_url)

```

Once the link user flow is completed, the user will be redirected back to the `redirect_uri` specified in the `authorizationParams`. At that point, it's required to call `completeLinkUser()` to finalize the user-linking process. Read more below in [Completing Link User](#completing-link-user).

### Passing `authorization_params`

You can customize the parameters passed to the /authorize endpoint in two ways:

1. Globally:
    Configure them when instantiating the ServerClient:
    ```python
    server_client = ServerClient(
        domain="demo.iam-federatedat-2.auth0c.com",
        client_id="your_client_id",
        client_secret="your_client_secret",
        redirect_uri="http://localhost:3000/auth/callback",
        secret="your_secret",
        authorization_params={
            "audience": "urn:custom:api",
            "scope": "openid profile email offline_access"
        }
    )
    ```

2. Per-call Override:
    Supply them when calling `start_link_user()`. Options provided here will override the global settings:


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
> [!NOTE]
> Keep in mind that, any `authorization_params` property specified when calling `start_link_user`, will override the same, statically configured, `authorization_params` property on `ServerClient`.


### Passing `appState` to track state during login

The `appState` parameter allows you to pass custom data (for example, a returnTo URL) that will be returned when the linking process is complete.

```python
options = {
    "appState": {"returnTo": "http://localhost:3000/dashboard"}
}
link_user_url = await server_client.start_link_user(options, store_options=store_options)
# Later, when completing linking:
result = await server_client.complete_link_user(callback_url, store_options=store_options)
print(result.get("appState").get("returnTo"))  # Should output "http://localhost:3000/dashboard"

```

> [!TIP]
> Using `appState` can be useful for a variaty of reasons, but is mostly supported to enable using a `returnTo` parameter in framework-specific SDKs that use `auth0-server-python`.

### Passing `StoreOptions`
Every method that interacts with the state or transaction store accepts a second parameter, `store_options`. This parameter should include the HTTP request and response objects (or equivalents) needed to manage cookies or sessions.

```python
store_options = {"request": request, "response": response}
link_user_url = await server_client.start_link_user(options, store_options=store_options)

```

Read more above in [Configuring the Transaction and State Store](#configuring-the-transaction-and-state-store)

## Complete Linking The User

After the user has been redirected back to your application (at the` redirect_uri`), you need to complete the linking process. This is done by calling `complete_link_user()`, which extracts the necessary parameters from the callback URL and returns the `appState`.

```python
# Complete the linking process:
result = await server_client.complete_link_user(callback_url, store_options=store_options)
# Retrieve the appState:
print(result.get("appState").get("returnTo"))
```

> [!NOTE]
> TThe URL passed to `complete_link_user()` should be the full callback URL from Auth0, including the `state` and `code` parameters.


### Passing `StoreOptions`

Just like most methods, `complete_link_user()` accept a second argument that is used to pass to the configured Transaction and State Store:

```python
store_options = {"request": request, "response": response}
link_user_url = await server_client.start_link_user(options, store_options=store_options)
```

Read more above in [Configuring the Transaction and State Store](#configuring-the-transaction-and-state-store)
