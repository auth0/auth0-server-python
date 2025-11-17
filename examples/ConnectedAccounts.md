# Connect Accounts for using Token Vault

The Connect Accounts feature uses the Auth0 My Account API to allow users to link multiple third party accounts to a single Auth0 user profile. In order to use this feature, [My Account API](https://auth0.com/docs/manage-users/my-account-api) must be activated on your Auth0 tenant. 

>[!NOTE]
>DPoP sender token constraining is not yet supported in this SDK. My Account API can be configured to support it (default behaviour) but must not be configured to require it.


When using Connected Accounts, Auth0 acquires tokens from upstream Identity Providers (like Google) and stores them in a secure [Token Vault](https://auth0.com/docs/secure/tokens/token-vault). These tokens can then be used to access third-party APIs (like Google Calendar) on behalf of the user.

The tokens in the Token Vault are then accessible to [Resource Servers](https://auth0.com/docs/get-started/apis) (APIs) configured in Auth0. The application can then issue requests to the API, which can retrieve the tokens from the Token Vault and use them to access the third-party APIs.

This is particularly useful for applications that require access to different resources on behalf of a user, like AI Agents.

## Configure the SDK

The Auth0 client Application must be configured to use refresh tokens and [MRRT (Multiple Resource Refresh Tokens)](https://auth0.com/docs/secure/tokens/refresh-tokens/multi-resource-refresh-token) since we will use the refresh token grant to get Access Tokens for the My Account API in addition to the API we are calling.

```python
server_client = ServerClient(
    domain="YOUR_AUTH0_DOMAIN",
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    secret="YOUR_SECRET",
    authorization_params={
        "redirect_uri":"YOUR_CALLBACK_URL",
        "audience": "YOUR_API_IDENTIFIER"
    }
)
```

## Login to the application

Use the login methods to authenticate to the application and get a refresh and access token for the API.

```python
# Login specifying any scopes for the Auth0 API

authorization_url = await server_client.start_interactive_login(
    {
        "authorization_params": {
            # must include offline_access to obtain a refresh token
            "scope": "openid profile email offline_access"
        }
    },
    store_options={"request": request, "response": response}
)

# redirect user

# handle redirect
result = await server_client.complete_interactive_login(
    callback_url, 
    store_options={"request": request, "response": response}
)
```

## Connect to a third-party account

Start the flow using the `start_connect_account` method to redirect the user to the third-party Identity Provider to connect their account.

The `authorization_params` is used to pass additional parameters required by the third-party IdP
The `app_state` parameter allows you to pass custom state (for example, a return URL) that is later available when the connect process completes.

```python

connect_url = await self.client.start_connect_account(
    ConnectAccountOptions(
        connection="CONNECTION", # e.g. google-oauth2
        redirect_uri="YOUR_CALLBACK_URL"
        app_state= { 
            "returnUrl":"SOME_URL"
        }
        scopes= [ 
            # scopes to passed to the third-party IdP
            "openid",
            "email",
            "profile"
            "offline_access"
        ]
        authorization_params= {
            # additional auth parameters to be sent to the third-party IdP e.g.
            "login_hint": "user123",
            "resource": "some_resource"
        }
    ), 
    store_options={"request": request, "response": response}
)
```

Using the url returned, redirect the user to the third-party Identity Provider to complete any required authorization. Once authorized, the user will be redirected back to the provided `redirect_uri` with a `connect_code` and `state` parameter.

## Complete the account connection

Call the `complete_connect_account` method using the full callback url returned from the third-party IdP to complete the connected account flow. This method extracts the connect_code from the URL, completes the connection, and returns the response data (including any `app_state` you passed originally).

```python
complete_response = await self.client.complete_connect_account(
    url= callback_url, 
    store_options=store_options
)
```

>[!NOTE]
>The `callback_url` must include the necessary parameters (`state` and `connect_code`) that Auth0 sends upon successful authentication.

You can now call the API with your access token and the API can use [Access Token Exchange with Token Vault](https://auth0.com/docs/secure/tokens/token-vault/access-token-exchange-with-token-vault) to get tokens from the Token Vault to access third-party APIs on behalf of the user.