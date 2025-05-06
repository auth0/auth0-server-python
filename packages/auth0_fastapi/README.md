The Auth0 FastAPI SDK is a library for implementing user authentication in FastAPI web applications using [Auth0](https://auth0.com).

![Release](https://img.shields.io/pypi/v/auth0-fastapi) [![Codecov](https://img.shields.io/codecov/c/github/auth0/auth0-fastapi)](https://codecov.io/gh/auth0/auth0-fastapi) ![Downloads](https://img.shields.io/pypi/dw/auth0-fastapi) [![License](https://img.shields.io/:license-MIT-blue.svg?style=flat)](https://opensource.org/licenses/MIT)

📚 [Documentation](#documentation) - 🚀 [Getting Started](#getting-started) - 💬 [Feedback](#feedback)

## Documentation

- [Examples](https://github.com/auth0/auth0-server-python/blob/main/packages/auth0_server_python/examples) - examples for your different use cases.
- [Docs Site](https://auth0.com/docs) - explore our docs site and learn more about Auth0.

## Getting Started

- [1. Features](#1-features)
- [2. Installation](#2-installation)
- [3. Setup](#2-setup)
  - [Minimal Setup](#minimal)
  - [Advanced](#advanced)
- [4. Routes](#4-routes)
  - [Protecting Routes](#protecting-routes)

### 1. Features

- **Fully Integrated Auth Flows**: Automatic routes for `/auth/login`, `/auth/logout`, `/auth/callback`, etc.
- **Session-Based**: Uses secure cookies to store user sessions, either stateless (all data in cookie) or stateful (data in a database).
- **Account Linking**: Optional routes for linking multiple social or username/password accounts into a single Auth0 profile.
- **Backchannel Logout**: Receive logout tokens from Auth0 to invalidate sessions server-side.
- **Extensible**: Swap in your own store implementations or tune existing ones (cookie name, expiration, etc.)

### 2. Installation

> _Requirements: Python 3.9+ and FastAPI. A typical production environment also requires HTTPS so that secure cookies (`secure=True`) can be sent._

```shell
pip install auth0-fastapi
```

If you’re using Poetry:

```shell
poetry install auth0-fastapi
```

### 3. Setup
#### Minimal

```python
# main.py
import os
import uvicorn
from fastapi import FastAPI, Depends, Request, Response
from starlette.middleware.sessions import SessionMiddleware

from auth0_fastapi.config import Auth0Config
from auth0_fastapi.auth.auth_client import AuthClient
from auth0_fastapi.server.routes import router, register_auth_routes
from auth0_fastapi.errors import register_exception_handlers

app = FastAPI(title="Auth0-FastAPI Example")

# 1) Add Session Middleware, needed if you're storing data in (or rely on) session cookies
app.add_middleware(SessionMiddleware, secret_key="YOUR_SESSION_SECRET")

# 2) Create an Auth0Config with your Auth0 credentials & app settings
config = Auth0Config(
    domain="YOUR_AUTH0_DOMAIN",          # e.g., "dev-1234abcd.us.auth0.com"
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    app_base_url="http://localhost:3000",  # or your production URL
    secret="YOUR_SESSION_SECRET"
)

# 3) Instantiate the AuthClient
auth_client = AuthClient(config)

# Attach to the FastAPI app state so internal routes can access it
app.state.config = config
app.state.auth_client = auth_client

# 4) Conditionally register routes
register_auth_routes(router, config)

# 5) Include the SDK’s default routes
app.include_router(router)


@app.get("/")
def home():
    return {"message": "Hello, Auth0-FastAPI!"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=3000)
```

#### Auth0 Dashboard Configurations

- The `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`, and `AUTH0_CLIENT_SECRET` can be obtained from the [Auth0 Dashboard](https://manage.auth0.com) once you've created an application. **This application must be a `Regular Web Application`**.

- The `SESSION_SECRET` is the key used to encrypt the session and transaction cookies. You can generate a secret using `openssl`:

```shell
openssl rand -hex 64
```

- The `APP_BASE_URL` is the URL that your application is running on. When developing locally, this is most commonly `http://localhost:3000`.

> [!IMPORTANT]  
> You will need to register the following URLs in your Auth0 Application via the [Auth0 Dashboard](https://manage.auth0.com):
>
> - Add `http://localhost:3000/auth/callback` to the list of **Allowed Callback URLs**
> - Add `http://localhost:3000` to the list of **Allowed Logout URLs**

#### Advanced

If you need more control over session management, transaction cookies, or additional settings, here’s a more extensive setup.

##### Customizing the Cookie Stores

By default, the SDK creates:

- A _stateless state store_: keeps session data encrypted directly in the cookie, or you can switch to a _Stateful store_ (backed by Redis or another database).
- A _cookie transaction store_: for short-lived transaction data.

To tweak these stores - to change cookie names or expiration dates - or to use a custom store, simply instantiate your store and pass it to `AuthClient`:

```python
# main.py
import os
import uvicorn
from fastapi import FastAPI, Depends, Request, Response
from starlette.middleware.sessions import SessionMiddleware

from auth0_fastapi.config import Auth0Config
from auth0_fastapi.auth.auth_client import AuthClient
from auth0_fastapi.server.routes import router, register_auth_routes
from auth0_fastapi.errors import register_exception_handlers

app = FastAPI(title="Auth0 FastAPI Example")

# 1) Add Session Middleware, needed if you're storing data in (or rely on) session cookies
app.add_middleware(SessionMiddleware, secret_key=os.environ.get("SESSION_SECRET"))

# 2) Create an Auth0Config with your Auth0 credentials & app settings
config = Auth0Config(
    domain="YOUR_AUTH0_DOMAIN",          # e.g., "dev-1234abcd.us.auth0.com"
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    app_base_url="http://localhost:3000",  # or your production URL
    secret="YOUR_SESSION_SECRET",
)

# 3) Instantiate the AuthClient
auth_client = AuthClient(config)

# Attach to the FastAPI app state so internal routes can access it
app.state.config = config
app.state.auth_client = auth_client

# 4) Conditionally register routes
register_auth_routes(router, config)

# 5) Include the SDK’s default routes
app.include_router(router)
```

#### 4. Routes

The SDK for Web Applications mounts 4 main routes:

1. `/auth/login`: the login route that the user will be redirected to to initiate an authentication transaction
2. `/auth/logout`: the logout route that must be added to your Auth0 application's Allowed Logout URLs
3. `/auth/callback`: the callback route that must be added to your Auth0 application's Allowed Callback URLs
4. `/auth/backchannel-logout`: the route that will receive a `logout_token` when a configured Back-Channel Logout initiator occurs

To disable this behavior, you can set the `mount_routes` option to `False` (it's `True` by default):

```python
config = Auth0Config(
    domain="YOUR_AUTH0_DOMAIN",    
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    app_base_url="http://localhost:3000",
    secret="YOUR_SESSION_SECRET",
    mount_routes=False,
)
```

Additionally, by setting `mount_connect_routes` to `True` (it's `False` by default) the SDK also can also mount 4 routes useful for account-linking:

1. `/auth/connect`: the route that the user will be redirected to to initiate account linking
2. `/auth/connect/callback`: the callback route for account linking that must be added to your Auth0 application's Allowed Callback URLs
3. `/auth/unconnect`: the route that the user will be redirected to to initiate account linking
4. `/auth/unconnect/callback`: the callback route for account linking that must be added to your Auth0 application's Allowed Callback URLs


#### Protecting Routes

In order to protect a FastAPI route, you can use the SDK's `get_session()` method and pass it through `Depends`:

```python
from fastapi import Depends, Request, Response, HTTPException, status
from auth0_fastapi.config import Auth0Config
from auth0_fastapi.auth.auth_client import AuthClient


config = Auth0Config(
    domain="YOUR_AUTH0_DOMAIN",            # e.g., "dev-1234abcd.us.auth0.com"
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    app_base_url="http://localhost:3000",  # or your production URL
    secret="YOUR_SESSION_SECRET",
    authorization_params={
        "scope": "openid profile",         # required get the user information from Auth0
    }
)

auth_client = AuthClient(config)


@app.get("/profile")
async def profile(request: Request, response: Response, session=Depends(auth_client.require_session)):
    store_options = {"request": request, "response": response}
    user = await auth_client.client.get_user(store_options=store_options)
    if not user:
        return {"error": "User not authenticated"}
    
    return {
        "message": "Your Profile",
        "user": user,
        "session_details": session
    }
```

> [!IMPORTANT]  
> The above is to protect server-side rendering routes by the means of a session, and not API routes using a bearer token.
> The `authorization_params` passing the `scope` is used in to retrieve the user information from Auth0. Can be omitted if you don't need the user information.


#### Requesting an Access Token to call an API

If you need to call an API on behalf of the user, you want to specify the `audience` parameter when registering the plugin. This will make the SDK request an access token for the specified audience when the user logs in.

```python
config = Auth0Config(
    domain="YOUR_AUTH0_DOMAIN",    
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    app_base_url="http://localhost:3000",
    secret="YOUR_SESSION_SECRET"
    auhorization_params= {
      "audience": "YOUR_AUDIENCE"
    }
)
```

The `AUTH0_AUDIENCE` is the identifier of the API you want to call. You can find this in the [APIs section of the Auth0 Dashboard](https://manage.auth0.com/#/apis/).

## Feedback

### Contributing

We appreciate feedback and contribution to this repo! Before you get started, please read the following:

- [Auth0's general contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)
- [Auth0's code of conduct guidelines](https://github.com/auth0/open-source-template/blob/master/CODE-OF-CONDUCT.md)
- [This repo's contribution guide](./../../CONTRIBUTING.md)

### Raise an issue

To provide feedback or report a bug, please [raise an issue on our issue tracker](https://github.com/auth0/auth0-fastapi/issues).

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
  This project is licensed under the MIT license. See the <a href="https://github.com/auth0/auth0-server-python/blob/main/packages/auth0_fastapi/LICENSE"> LICENSE</a> file for more info.
</p>
