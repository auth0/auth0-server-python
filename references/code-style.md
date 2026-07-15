# Code Style

## Formatting & linting (CI-enforced)

- **Tool:** ruff (`.ruff.toml`), line length 100, `target-version = py39`. CI runs `ruff check .` and fails on violations.
- **Enabled rule sets:** `E`/`W` (pycodestyle), `F` (pyflakes), `I` (isort — keep imports sorted/grouped), `B` (bugbear), `C4` (comprehensions), `UP` (pyupgrade — use modern Python idioms), `S` (bandit security), `PLC0415` (no imports inside functions).
- **Ignored:** `E501` (line length handled separately), `B904`, `S101`/`S105`/`S106` (assert + hardcoded-password heuristics that misfire in tests).

## Naming & idiom

- Idiomatic Python: `snake_case` for functions/variables, `PascalCase` for classes, module-level constants `UPPER_SNAKE`.
- The SDK is **async-first** and **type-annotated**: public methods are `async def` with full type hints; options are typed (Pydantic models in `auth_types/`, `Generic[TStoreOptions]`).
- Errors come from the `Auth0Error` hierarchy in `error/` — define a new subclass rather than raising a bare `Exception`.

**✅ Good:**

```python
async def get_user(self, store_options: Optional[dict[str, Any]] = None) -> Optional[dict[str, Any]]:
    session = await self.get_session(store_options)
    if session is None:
        return None
    return session.get("user")
```

**❌ Bad:**

```python
def get_user(self, store_options=None):        # not async, no type hints
    session = self.get_session(store_options)   # missing await on a coroutine
    try:
        return session["user"]
    except Exception:                           # bare except instead of an Auth0Error
        return None
```

## Patterns

- **Pluggable storage:** state/session persistence goes through `AbstractDataStore` / `StateStore` — depend on the abstraction, don't hardcode a backend.
- **Encrypted state:** stored state is encrypted via `encryption/encrypt.py`; don't persist plaintext session data.
- **Cached OIDC/JWKS:** metadata and JWKS are fetched once and cached — reuse the cached helpers rather than re-fetching.
