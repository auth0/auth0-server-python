# Connect Accounts for using Token Vault

The Connect Accounts feature uses the Auth0 My Account API to allow users to link multiple third party accounts to a single Auth0 user profile. In order to use this feature, [My Account API](https://auth0.com/docs/manage-users/my-account-api) must be activated on your Auth0 tenant. 

>[!NOTE]
>DPoP sender token constraining is not yet supported in this SDK. My Account API can be configured to support it (default behaviour) but must not be configured to require it.


When using [Connected Accounts for Token Vault](https://auth0.com/docs/secure/tokens/token-vault/connected-accounts-for-token-vault), Auth0 acquires tokens from upstream Identity Providers (like Google) and stores them in a secure [Token Vault](https://auth0.com/docs/secure/tokens/token-vault). These tokens can then be used to access third-party APIs (like Google Calendar) on behalf of the user.

The tokens in the Token Vault are then accessible to [Applications](https://auth0.com/docs/get-started/applications) configured in Auth0. The application can issue requests to Auth0 to retrieve the tokens from the Token Vault and use them to access the third-party APIs.

This is particularly useful for applications that require access to different resources on behalf of a user, like AI Agents.

## Pre-requisites
Connected Account functionality makes use of the Auth0 [My Account API] (https://auth0.com/docs/manage-users/my-account-api) and [Multiple Resource Refresh Tokens (MRRT)](https://auth0.com/docs/secure/tokens/refresh-tokens/multi-resource-refresh-token). To use this functionality in this SDK you must first ensure that you first [activate My Account API](https://auth0.com/docs/manage-users/my-account-api#activate-the-my-account-api) on your Auth0 tenant and enable access for you client Application. You must also [configure MRRT](https://auth0.com/docs/secure/tokens/refresh-tokens/multi-resource-refresh-token/configure-and-implement-multi-resource-refresh-token#configure-applications-for-mrrt) on your client application's refresh token policies to allow access to the My Account audience (`https://{yourDomain}/me/`) for the `create:me:connected_accounts` scope as well as any other APIs and scopes you intend to access in your application.

## Configure the SDK

```python
server_client = ServerClient(
    domain="YOUR_AUTH0_DOMAIN",
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    secret="YOUR_SECRET",

)
```

## Login to the application

Use the login methods to authenticate to the application and get a refresh token in order to use MRRT to call the My Account API. If you are also intending to authorize access to any custom API, you may optionally specify an audience and any relevant scopes but you must at a minimum include the `offline_access` scope to ensure you obtain a refresh token.

```python
# Login to authenticate your aplication, optionally specifying any scopes for your Auth0 API
authorization_url = await server_client.start_interactive_login(
    {
        "redirect_uri": "CALLBACK_URL",
        "authorization_params": {
            # optional
            "audience": "https://custom-api.com",
            # must include at least offline_access to obtain a refresh token
            "scope": "offline_access openid profile email read:foo"
        }
    },
    store_options={"request": request, "response": response}
)
```
Redirect user to the provided url, after authenticating with Auth0, the user will be returned to the provided `CALLBACK_URL` with additional `state` and `code` query parameters. In the handler for this callback, complete the interactive login passing the full callback url (including any query parameters).

```python
# handle redirect
result = await server_client.complete_interactive_login(
    full_callback_url, 
    store_options={"request": request, "response": response}
)
```

## Connect to a third-party account

Start the flow using the `start_connect_account` method to redirect the user to the third-party Identity Provider to connect their account.

The `authorization_params` is used to pass additional parameters required by the third-party IdP.

The `scopes` parameter is used to override the scopes requested from the third-party IdP. By default, if no `scopes` parameter is provided, Auth0 will request any scopes configured in the connection settings through the Auth0 Management API/Dashboard.

The `app_state` parameter allows you to pass custom state (for example, a return URL) that is later available when the connect process completes.

```python

connect_url = await self.client.start_connect_account(
    ConnectAccountOptions(
        connection="google-oauth2",
        redirect_uri="CALLBACK_URL"
        app_state= {
            "returnUrl":"SOME_URL"
        }
        scopes= [
            # scopes to passed to the third-party IdP
            "openid",
            "https://www.googleapis.com/auth/calendar.freebusy",
            "https://www.googleapis.com/auth/calendar.readonly"
        ]
        authorization_params= {
            # additional auth parameters to be sent to the third-party IdP
            "login_hint": "jdoe@example.org"
        }
    ),
    store_options={"request": request, "response": response}
)
```

Using the url returned, redirect the user to the third-party Identity Provider to complete any required authorization. Once authorized, the user will be redirected back to the provided `CALLBACK_URL` with a `connect_code` and `state` parameter. The `CALLBACK_URL` provided may be the same that is used for the interative login or it may be distinct. However if the same endpoint is used, the handler should be able distinguish between a login callback vs a connect accounts callback (typically via the presence of the `code` and `connect_code` parameter respectively).

## Complete the account connection

In the callback handler, call the `complete_connect_account` method using the full callback url returned from the third-party IdP to complete the connected account flow. This method extracts the connect_code from the URL, completes the connection, and returns the response data (including any `app_state` you passed originally).

```python
complete_response = await self.client.complete_connect_account(
    url= connect_account_full_callback_url, 
    store_options={"request": request, "response": response}
)
```

>[!NOTE]
>The `callback_url` must include the necessary parameters (`state` and `connect_code`) that Auth0 sends upon successful authorization.

You can now call the API with your access token and the API can use [Access Token Exchange with Token Vault](https://auth0.com/docs/secure/tokens/token-vault/access-token-exchange-with-token-vault) to get tokens from the Token Vault to access third-party APIs on behalf of the user.

```python
access_token_for_google = await server_client.get_access_token_for_connection(
    { "connection": "google-oauth2" }, 
    store_options=store_options
)
```