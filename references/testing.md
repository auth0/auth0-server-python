# Testing Conventions

- **Framework:** pytest `^7.2` with `pytest-asyncio` (`>=0.20.3,<0.24.0`), `pytest-mock` `^3.14`, `pytest-cov` `^4.0`
- **Location:** `src/auth0_server_python/tests/` — one `test_<module>.py` per source module
- **Coverage:** `pytest-cov`, configured in `pyproject.toml` `addopts`; reports to terminal and `coverage.xml`
- **Threshold:** none configured — no `fail_under` in `pyproject.toml`, and the codecov upload step in
  `test.yml` is commented out. Coverage is informational, not a gate.

## Async tests need an explicit marker

There is **no** `asyncio_mode = "auto"` in `pyproject.toml`. Every async test must carry the marker
or it is collected and silently skipped as a coroutine that never runs:

```python
@pytest.mark.asyncio
async def test_resolver_returning_none_raises(self):
    ...
```

## Naming

`test_<subject>_<condition>_<expected>` — descriptive and long is preferred over terse:

- `test_init_no_secret_raises`
- `test_start_interactive_login_no_redirect_uri`
- `test_resolver_exception_wrapped_in_domain_resolver_error`

## Organization

Two shapes coexist; match the file you're editing.

- **Module-level functions** — `test_server_client.py` and `test_dpop_auth.py`
- **Grouping classes** — `test_mfa_client.py`, `test_my_account_client.py` use `TestMfaClientConstructor`,
  `TestDomainResolution`, etc., with `# ── Section ───` comment banners between groups

## Fixtures and factories

No `conftest.py` exists. Shared setup lives as module-level constants plus small private factory
helpers in each test file:

```python
DOMAIN = "auth0.local"
CLIENT_ID = "<client_id>"
CLIENT_SECRET = "<client_secret>"
SECRET = "test-secret-long-enough-for-encryption"


def _make_client() -> MfaClient:
    return MfaClient(domain=DOMAIN, client_id=CLIENT_ID,
                     client_secret=CLIENT_SECRET, secret=SECRET)
```

Placeholder credentials are angle-bracketed (`<client_id>`) or obviously synthetic — keep it that
way; never paste a real tenant value into a test.

## Mocking

- `unittest.mock.AsyncMock` for the `state_store` / `transaction_store` passed into `ServerClient`
- `MagicMock` for sync collaborators, `ANY` for arguments you don't want to pin
- `mocker` (pytest-mock) where a patch should unwind automatically; `patch(...)` as a context manager elsewhere
- `httpx` calls are mocked at the client boundary — no live HTTP, no recorded cassettes
- Real `jwcrypto.jwk` keys are generated in-test for DPoP coverage rather than mocked, so proofs
  actually verify

## Assertions

Plain `assert`, plus `pytest.raises` for the typed-error paths — which is most of the suite:

```python
with pytest.raises(MissingRequiredArgumentError) as exc:
    ServerClient(domain="example.auth0.com", client_id="id", client_secret="secret")
assert "secret" in str(exc.value)
```

Assert on the error's **`code`** (or its `Auth0Error` subclass) rather than on message text where
both are available — messages are not part of the contract, codes are.
