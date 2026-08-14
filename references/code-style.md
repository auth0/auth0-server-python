# Code Style

Linter config: `.ruff.toml` (repo root — not `[tool.ruff]` in `pyproject.toml`).

## Enforced rule sets

`select = ["E", "W", "F", "I", "B", "C4", "UP", "S", "PLC0415"]` — pycodestyle, pyflakes, isort,
bugbear, comprehensions, pyupgrade, **bandit (security)**, and no-import-outside-top-level.

`ignore = ["E501", "B904", "S101", "S105", "S106"]` — line length is not enforced despite
`line-length = 100`; `raise ... from` is optional; `assert` and hardcoded-password-string warnings are
off (for tests and for kwargs like `client_secret=`).

`target-version = "py39"` — pyupgrade will not rewrite to 3.10+ syntax, and must not.

## Naming

| Kind | Convention | Example |
|------|-----------|---------|
| Modules / packages | `snake_case` | `my_account_client.py`, `auth_schemes/` |
| Classes | `PascalCase` | `ServerClient`, `MyAccountApiError`, `DPoPAuth` |
| Public methods | `snake_case`, verb-first | `start_interactive_login`, `get_access_token_for_connection` |
| Internal methods | `_` prefix | `_resolve_current_domain`, `_get_http_client` |
| Instance state | `_` prefix | `self._client_id`, `self._telemetry_headers` |
| Class constants | `UPPER_SNAKE` | `GRANT_TYPE_PASSKEY`, `PASSKEY_REGISTER_PATH` |
| Module constants | `UPPER_SNAKE` | `ENC`, `ALG`, `SESSION_EXPIRY_MAX_PLAUSIBLE` |
| Error codes | `UPPER_SNAKE` on a code class | `AccessTokenErrorCode.SESSION_EXPIRED` |

Two-step flows name themselves: `start_*` / `complete_*` (`start_link_user` → `complete_link_user`),
and challenge-then-exchange flows use `*_challenge` → `signin_with_*`.

## ✅ Good — the dominant public-method shape

```python
async def passkey_login_challenge(
    self,
    username: Optional[str] = None,
    connection: Optional[str] = None,
    organization: Optional[str] = None,
    store_options: Optional[dict[str, Any]] = None,
) -> PasskeyLoginChallengeResponse:
    """
    Step 1 of 2: Initiate a passkey login challenge (POST /passkey/challenge).

    Args:
        username: ...
        store_options: Optional options for domain resolution.

    Returns:
        PasskeyLoginChallengeResponse with auth_session and authn_params_public_key.

    Raises:
        PasskeyError: If the challenge request fails.
    """
    try:
        domain = await self._resolve_current_domain(store_options)
        async with self._get_http_client() as client:
            response = await client.post(f"https://{domain}{self.PASSKEY_CHALLENGE_PATH}", json=body)
            if response.status_code != 200:
                error_data = response.json()
                raise PasskeyError(
                    error_data.get("error", PasskeyErrorCode.CHALLENGE_FAILED),
                    error_data.get("error_description", "Passkey login challenge failed"),
                )
            return PasskeyLoginChallengeResponse.model_validate(response.json())
    except Exception as e:
        if isinstance(e, (PasskeyError, MissingRequiredArgumentError, ValidationError)):
            raise
        raise PasskeyError(PasskeyErrorCode.CHALLENGE_FAILED, "Passkey login challenge failed", e) from e
```

What makes it conform:

- `async` + keyword-only-ish optional params, every one typed, `Optional[...]` (not `X | None` — py39 floor)
- returns a **Pydantic model**, validated via `model_validate` — never a raw `dict`
- `store_options` threaded through so MCD domain resolution works
- Google-style docstring with `Args` / `Returns` / `Raises`
- `async with self._get_http_client()` — the telemetry-carrying client, never a bare `httpx.AsyncClient`
- catch-all re-raises the SDK's own typed errors untouched, then wraps anything unexpected in a typed
  error with a code, chaining the cause

## ❌ Bad

```python
def passkey_login_challenge(self, username=None, store_options=None):   # sync, untyped
    client = httpx.AsyncClient()                                        # bypasses telemetry headers
    response = client.post(f"https://{self._domain}/passkey/challenge",  # ignores MCD resolver
                           json={"username": username})
    if response.status_code != 200:
        print(f"failed: {response.text}")                               # logs a response body
        return None                                                     # fails open, untyped
    return response.json()                                              # unvalidated dict escapes
```

Each line is a separate violation: sync in an async SDK, an un-instrumented HTTP client, a static
domain in an MCD-capable path, a print of a possibly token-bearing body, a `None` return that a caller
can mistake for "no passkey" instead of "request failed", and an unvalidated `dict` in the public API.

## Patterns in use

- **Generic client over the store type** — `ServerClient(Generic[TStoreOptions])`; store implementations
  subclass `StateStore` / `TransactionStore` from `store/abstract.py` (template method: the ABC owns
  `encrypt`/`decrypt`, subclasses own `set`/`get`/`delete`)
- **Sub-client composition** — `ServerClient` owns `MfaClient` and `MyAccountClient`; MFA is exposed
  through the read-only `mfa` property, and connected-accounts calls delegate to `_my_account_client`
- **`httpx.Auth` strategies** — `BearerAuth` and `DPoPAuth` in `auth_schemes/`, selected by a
  `_make_auth(access_token, dpop_key)` helper. Add a new scheme as another `httpx.Auth`, not as
  inline header-setting.
- **Pydantic models as the wire contract** — everything in `auth_types/__init__.py`; caller-supplied
  enums are `Literal[...]` while server-returned fields stay `str` so a new Auth0 factor type doesn't
  fail closed
- **Flat typed error hierarchy** — every error subclasses `Auth0Error` and carries a stable `code`;
  code enumeration classes (`AccessTokenErrorCode`, `PasskeyErrorCode`, …) hold the string constants
- **PEP 562 module `__getattr__`** for deprecated public aliases (`auth_types._DEPRECATED_ALIASES`) —
  the import keeps working and emits a `DeprecationWarning`. Follow this when retiring a public name.
- **Section banners** — long modules are divided with `# ====== SECTION ======` comment blocks;
  keep new methods inside the matching section and preserve existing declaration order.
- **Deliberate placement, even without banners** — in a file with no section banners, put a new
  method/class/function next to the related code it belongs with, or append it at the end of the
  file/class. Never insert one at an arbitrary position just because it compiles there.

## Comments

Code is largely self-documenting; comments are reserved for *why* — a protocol citation
(`# RFC 9449 §8.2 — server-nonce retry`), a non-obvious security decision (`# NFC-normalize before
comparison...`), or an intentional omission (`# redirect_uri is intentionally excluded — in MCD mode
it is built dynamically`). Don't add comments that restate the code.
