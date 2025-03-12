The Auth0-Server-Python SDK is a library for implementing user authentication in Fast API Python applications.

![Release](https://img.shields.io/pypi/v/auth0-python)
[![Codecov](https://img.shields.io/codecov/c/github/auth0/auth0-python)](https://codecov.io/gh/auth0/auth0-python)
![Downloads](https://img.shields.io/pypi/dw/auth0-python)
[![License](https://img.shields.io/:license-MIT-blue.svg?style=flat)](https://opensource.org/licenses/MIT)
[![CircleCI](https://img.shields.io/circleci/build/github/auth0/auth0-python)](https://circleci.com/gh/auth0/auth0-python)

📚 [Documentation](#documentation) - 🚀 [Getting Started](#getting-started) - 💻 [API Reference](https://auth0.github.io/auth0-server-js/) - 💬 [Feedback](#feedback)

## Documentation

- [Examples](https://github.com/auth0/auth0-server-python/blob/main/packages/auth0-server-python/EXAMPLES.md) - examples for your different use cases.
- [Docs Site](https://auth0.com/docs) - explore our docs site and learn more about Auth0.

## Getting Started

### 1. Install the SDK

```shell
pip install auth0-server-python
```

This library requires Node.js 20 LTS and newer LTS versions.

### 2. Create the Auth0 SDK client

Create an instance of the Auth0 client. This instance will be imported and used in anywhere we need access to the authentication methods.


```python
from auth0-server-python import ServerClient

auth0 = ServerClient(
    domain='<AUTH0_DOMAIN>',
    client_id='<AUTH0_CLIENT_ID>',
    client_secret='<AUTH0_CLIENT_SECRET>',
    redirect_uri='<AUTH0_REDIRECT_URI>',
    secret='<AUTH0_SECRET>',
)
```

The `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`, and `AUTH0_CLIENT_SECRET` can be obtained from the [Auth0 Dashboard](https://manage.auth0.com) once you've created an application. **This application must be a `Regular Web Application`**.
The `AUTH0_REDIRECT_URI` is needed to tell Auth0 what URL to redirect back to after successfull authentication, e.g. `http://localhost:3000/auth/callback`. (note, your application needs to handle this endpoint and call the SDK's `completeInteractiveLogin(url: string)` to finish the authentication process. See below for more information)
The `AUTH0_SECRET` is the key used to encrypt the session and transaction cookies. You can generate a secret using `openssl`:

```shell
openssl rand -hex 64
```

### 3. Add login to your Application (interactive)

Before using redirect-based login, ensure the `redirect_uri` is configured when initializing the SDK:

```python
auth0 = ServerClient(
    # ...
    redirect_uri='<AUTH0_REDIRECT_URI>',
    # ...
)
```

> [!IMPORTANT]  
> You will need to register the `AUTH0_REDIRECT_URI` in your Auth0 Application as an **Allowed Callback URLs** via the [Auth0 Dashboard](https://manage.auth0.com):

In order to add login to any application, call `startInteractiveLogin()`, and redirect the user to the returned URL.

The implementation will vary based on the framework being used, but here is an example of what this would look like in Fastify:

```python
from fastapi import FastAPI, Request, Response
from starlette.responses import RedirectResponse

app = FastAPI()

@app.get("/auth/login")
async def login(request: Request):
    authorization_url = await auth0.start_interactive_login()
    return RedirectResponse(url=authorization_url)
});
```

Once the user has succesfully authenticated, Auth0 will redirect the user back to the provided `redirect_uri` which needs to be handled in the application.
This implementation will also vary based on the framework used, but what needs to happen is:

- register an endpoint that will handle the configured `redirect_uri`.
- call the SDK's `completeInteractiveLogin(url)`, passing it the full URL, including query parameters.

Here is an example of what this would look like in FastAPI, with `redirect_uri` configured as `http://localhost:3000/auth/callback`:

```python
@app.get("/auth/callback")
async def callback(request: Request):
    result = await auth0.complete_interactive_login(str(request.url))
    # Store session or set cookies as needed
    return RedirectResponse(url="/")
```

## Feedback

### Contributing

We appreciate feedback and contribution to this repo! Before you get started, please read the following:

- [Auth0's general contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)
- [Auth0's code of conduct guidelines](https://github.com/auth0/auth0-server-js/blob/main/CODE-OF-CONDUCT.md)
- [This repo's contribution guide](./CONTRIBUTING.md)

### Raise an issue

To provide feedback or report a bug, please [raise an issue on our issue tracker](https://github.com/auth0/auth0-server-js/issues).

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
  This project is licensed under the MIT license. See the <a href="https://github.com/auth0/auth0-server-js/blob/main/packages/auth0-fastify/LICENSE"> LICENSE</a> file for more info.
</p>