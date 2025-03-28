The `auth0-api-python` library allows you to secure APIs running on Python, particularly for verifying Auth0-issued access tokens.

It’s intended as a foundation for building more framework-specific integrations (e.g., with FastAPI, Django, etc.), but you can also use it directly in any Python server-side environment.

![Release](https://img.shields.io/pypi/v/auth0-api-python) ![Downloads](https://img.shields.io/pypi/dw/auth0-api-python) [![License](https://img.shields.io/:license-MIT-blue.svg?style=flat)](https://opensource.org/licenses/MIT)

📚 [Documentation](#documentation) - 🚀 [Getting Started](#getting-started) - 💬 [Feedback](#feedback)

## Documentation

- [Docs Site](https://auth0.com/docs) - explore our docs site and learn more about Auth0.

## Getting Started

### 1. Install the SDK

_This library requires Python 3.9+._

```shell
pip install auth0-api-python
```

If you’re using Poetry:

```shell
poetry install auth0-api-python
```

### 2. Create the Auth0 SDK client

Create an instance of the `ApiClient`. This instance will be imported and used anywhere we need access to the methods.

```python 
from auth0_api_python import ApiClient, ApiClientOptions


api_client = ApiClient(ApiClientOptions(
    domain="<AUTH0_DOMAIN>",
    audience="<AUTH0_AUDIENCE>"
))
```

- The `AUTH0_DOMAIN` can be obtained from the [Auth0 Dashboard](https://manage.auth0.com) once you've created an application.
- The `AUTH0_AUDIENCE` is the identifier of the API. You can find this in the [APIs section of the Auth0 Dashboard](https://manage.auth0.com/#/apis/).

### 3. Verify the Access Token

Use the `verify_access_token` method to validate access tokens. The method automatically checks critical claims like `iss`, `aud`, `exp`, `nbf`.

```python
import asyncio

from auth0_api_python import ApiClient, ApiClientOptions

async def main():
    api_client = ApiClient(ApiClientOptions(
        domain="<AUTH0_DOMAIN>",
        audience="<AUTH0_AUDIENCE>"
    ))
    access_token = "..."

    decoded_and_verified_token = await api_client.verify_access_token(access_token=access_token)
    print(decoded_and_verified_token)

asyncio.run(main())
```

In this example, the returned dictionary contains the decoded claims (like `sub`, `scope`, etc.) from the verified token.

#### Requiring Additional Claims

If your application demands extra claims, specify them with `required_claims`:

```python
decoded_and_verified_token = await api_client.verify_access_token(
    access_token=access_token,
    required_claims=["my_custom_claim"]
)
```

If the token lacks `my_custom_claim` or fails any standard check (issuer mismatch, expired token, invalid signature), the method raises a `VerifyAccessTokenError`.

## Feedback

### Contributing

We appreciate feedback and contribution to this repo! Before you get started, please read the following:

- [Auth0's general contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)
- [Auth0's code of conduct guidelines](https://github.com/auth0/open-source-template/blob/master/CODE-OF-CONDUCT.md)
- [This repo's contribution guide](./../../CONTRIBUTING.md)

### Raise an issue

To provide feedback or report a bug, please [raise an issue on our issue tracker](https://github.com/auth0/auth0-server-python/issues).

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
  This project is licensed under the MIT license. See the <a href="https://github.com/auth0/auth0-server-python/blob/main/packages/auth0_api_python/LICENSE"> LICENSE</a> file for more info.
</p>