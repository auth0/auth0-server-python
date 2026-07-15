# Testing

## Running

```bash
poetry run pytest
```

Runs the full suite with coverage (configured in `pyproject.toml` `addopts`: `--cov=auth0_server_python --cov-report=term-missing:skip-covered --cov-report=xml`). No credentials or live tenant required — everything is mocked. CI runs this across Python 3.9, 3.10, 3.11, 3.12.

## Location & framework

- Tests live in `src/auth0_server_python/tests/` (`test_server_client.py`, `test_mfa_client.py`, `test_my_account_client.py`, `test_telemetry.py`).
- **Framework:** pytest with `pytest-asyncio` and `pytest-mock`.

## Conventions

- The SDK is async, so most tests are coroutines — mark them with `@pytest.mark.asyncio`.
- Mock collaborators with `unittest.mock.AsyncMock` / `MagicMock` (and the `mocker` fixture from `pytest-mock`); pass `AsyncMock()` for `state_store` / `transaction_store` when constructing a `ServerClient`.
- Patch outbound HTTP (`httpx`) and OIDC-metadata/JWKS fetches rather than hitting the network.
- Name tests for the behavior under test, e.g. `test_start_interactive_login_no_redirect_uri`, `test_init_no_secret_raises`.

## Mocking pattern

```python
@pytest.mark.asyncio
async def test_something(mocker):
    client = ServerClient(
        ...,
        state_store=AsyncMock(),
        transaction_store=AsyncMock(),
        secret="test-secret",
    )
    mocker.patch.object(client, "_fetch_oidc_metadata", return_value={...})
    ...
```
