# Common Pitfalls

## 1. Python 3.9 is the floor — CI proves it on every PR

`pyproject.toml` declares `python = ">=3.9"` and `.ruff.toml` sets `target-version = "py39"`; the
version matrix CI actually runs lives in `.github/workflows/test.yml`. So:

- `Optional[X]` / `Union[X, Y]`, **not** `X | None` (PEP 604 is 3.10+)
- `match` statements, `ParamSpec` defaults, and `itertools.pairwise` are unavailable
- `dict[str, Any]` / `list[...]` builtin generics **are** fine (3.9 supports them) and are the house style

A 3.10-only construct passes locally on a newer interpreter and fails only the 3.9 leg.

## 2. `ruff format` is not a CI gate, and the tree is not format-clean

CI runs `ruff check .` only. Part of the tree has never been `ruff format`-ed, so running
`ruff format .` repo-wide produces a large diff unrelated to your change. Format only what you
touched; `poetry run ruff format --check .` lists the files that are already unformatted.

## 3. Async tests are skipped (with a warning), never executed, if you forget `@pytest.mark.asyncio`

`asyncio_mode` is not set to `auto` anywhere. An async test without the marker is collected but
skipped with a `PytestUnhandledCoroutineWarning`, never awaited. If a new async test shows up as
skipped (`s`) in the summary instead of passing, check for the marker first.

## 4. Never construct `httpx.AsyncClient` directly

`ServerClient._get_http_client()` merges `self._telemetry_headers`, and `MyAccountClient._get_http_client()`
merges `self._headers`, into every request (`ServerClient` constructs its `MyAccountClient` with
`headers=self._telemetry_headers`, so the header still reaches it). A hand-rolled client silently drops
the `Auth0-Client` header, so the call becomes invisible to SDK telemetry. Same reasoning for auth: use
`BearerAuth` / `DPoPAuth` from `auth_schemes/` rather than setting `Authorization` yourself.

## 5. `domain` may be a callable — resolve it, don't read it

MCD mode accepts `domain=<async resolver>` instead of a string. Any code path that builds a URL must
go through `await self._resolve_current_domain(store_options)` and thread `store_options` down to it.
Reading `self._domain` directly works in single-domain tests and breaks every MCD deployment. The
resolver failing raises `DomainResolverError` — it must never fall back to a default domain.

## 6. `store_options` is the integrator's request/response channel

Framework objects (`{"request": request, "response": response}`) reach cookie-backed stores only via
`store_options`. A new public method that forgets the parameter cannot be used by any cookie store —
which is the common integration. Every public flow method in `ServerClient` takes it; keep that.

## 7. Two Pydantic-typing rules that look interchangeable and aren't

In `auth_types/__init__.py`: caller-supplied values are `Literal[...]` so bad input is rejected at the
boundary; server-returned fields are plain `str` so a newly-added Auth0 factor or challenge type
doesn't fail closed and break existing users. Tightening a response field to a `Literal` is a
latent breaking change even though it type-checks.

## 8. `requirements.txt` and `pyproject.toml` both pin dependencies

Poetry resolves from `pyproject.toml` + `poetry.lock`; the Snyk SCA workflow installs from
`requirements.txt`. A dependency bump applied to only one of them either escapes the scan or breaks
the scan's install step.
