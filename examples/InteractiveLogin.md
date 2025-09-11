# Interactive Login

Interactive login in `auth0‑server‑python` is a two‑step process. First, you start the login flow by obtaining an authorization URL; then, after the user authenticates at Auth0 and is redirected back, you complete the login flow to exchange the authorization code for tokens. 

This guide covers how to customize the authorization parameters, pass custom app state, enable **Pushed Authorization Requests (PAR)** and **Rich Authorization Requests (RAR)**, and supply store options.

## 1. Starting Interactive Login

### Configuring the Redirect URI

Interactive login begins by configuring a redirect_uri—the URL Auth0 will use to send the user back after authentication. For example, when instantiating your core `ServerClient`:

```python
from auth_server.server_client import ServerClient

server_client = ServerClient(
    domain="YOUR_AUTH0_DOMAIN",
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    secret="YOUR_SECRET",
    authorization_params={
        "redirect_uri":"http://localhost:3000/auth/callback",
    }
)
```
Now call `start_interactive_login()` to obtain the authorization URL and redirect the user:
```python
authorization_url = await server_client.start_interactive_login()
```
## 2. Passing Authorization Params
You can customize the parameters sent to Auth0’s `/authorize` endpoint in two ways:

### Global Configuration

When creating your ServerClient, you can specify default parameters:

```python
server_client = ServerClient(
    domain="YOUR_AUTH0_DOMAIN",
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    redirect_uri="http://localhost:3000/auth/callback",
    secret="YOUR_SECRET",
    authorization_params={
        "scope": " your scopes",
        "audience": "urn:custom:api",
    }
)
```
### Dynamic Configuration Per Call
You can also override or add parameters when calling `start_interactive_login()`:
```python
authorization_url = await server_client.start_interactive_login({
    "authorization_params": {
        "scope": "openid profile email",
        "audience": "urn:custom:api",
        "foo": "bar"  # arbitrary custom parameter
    }
})
```
> [!NOTE]
> Any parameter specified here will override the corresponding global configuration.

## 3. Passing App State to Track State During Login

The `app_state` parameter allows you to pass custom state (for example, a return URL) that is later available when the login process completes.

```python
# Start interactive login with custom app state:
authorize_url = await server_client.start_interactive_login({
    "app_state": {"returnTo": "http://localhost:3000/dashboard"}
})

# Later, after completing login:
result = await server_client.complete_interactive_login(callback_url)
print(result.get("app_state").get("returnTo"))  # Should output: http://localhost:3000/dashboard
```
> [!NOTE]
>- `authorize_url` is the URL for Auth0’s /authorize endpoint (or a URL built from PAR, if enabled).
>- `callback_url` is the URL Auth0 redirects back to after authentication.

## 4. Using Pushed Authorization Requests (PAR)

To enable PAR, simply set the flag in your interactive login options. When enabled, the SDK will send an HTTP POST request with the authorization parameters to the PAR endpoint (retrieved from OIDC metadata) and use the returned `request_uri` to build the final authorization URL.
```python
# Enable PAR dynamically for a login call:
authorization_url = await server_client.start_interactive_login({
    "pushed_authorization_requests": True
})
```
>[!IMPORTANT]
> Using PAR requires that your Auth0 tenant is configured to support it. Refer to Auth0’s documentation for details.

## 5. Using Pushed Authorization Requests and Rich Authorization Requests (RAR)

When using PAR, you can also supply Rich Authorization Request details by including an `authorization_details` field in the `authorization_params`:
```python
import json

authorization_url = await server_client.start_interactive_login({
    "pushed_authorization_requests": True,
    "authorization_params": {
        "authorization_details": json.dumps([{
            "type": "your_type",
            "additional_field": "value"
        }])
    }
})
```
After completing the interactive login, the SDK will expose the `authorization_details` in the result:
```python
import json

authorization_url = await server_client.start_interactive_login({
result = await server_client.complete_interactive_login(callback_url)
print(result.get("authorization_details"))
```
>[!NOTE]
>Both PAR and RAR require that these features are enabled in your Auth0 dashboard.

## 6. Passing Store Options
Most methods in the SDK accept a second argument called `store_options`. This dictionary should include the HTTP Request and Response objects (or equivalent) that the store uses to manage cookies and session data.
```python
store_options = {"request": request, "response": response}
authorization_url = await server_client.start_interactive_login({}, store_options=store_options)
```
This enables the SDK to correctly read and set cookies for session management.

## 7.  Completing Interactive Login

After the user is redirected back to your callback URL from Auth0, you call `complete_interactive_login()` to finalize the authentication process. This method extracts the authorization code from the URL, exchanges it for tokens, and returns session data (including any app_state you passed originally, and—if using RAR—the `authorization_details`).
```python
result = await server_client.complete_interactive_login(callback_url, store_options={"request": request, "response": response})
print(result.get("app_state").get("returnTo"))           # Custom app state
print(result.get("authorization_details"))               # Rich Authorization Requests details (if any)

```

>[!NOTE]
>The `callback_url` must include the necessary parameters (`state` and `code`) that Auth0 sends upon successful authentication.