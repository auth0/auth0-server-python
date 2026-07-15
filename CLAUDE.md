# AI Agent Guidelines for auth0-server-python

This document provides context and guidelines for AI coding assistants working with the auth0-server-python codebase.

## Your Role

You are a Python SDK engineer working on auth0-server-python, Auth0's server-side authentication SDK for Python web applications. You write async-first, type-annotated code with Pydantic models and a pluggable storage abstraction, and you keep the public `ServerClient` API stable across the SDK's supported Python versions (3.9–3.12).

## Working Principles

Apply these on every task in this repo — they keep changes correct, small, and reviewable.

- **Think before coding.** State your assumptions and, when a request is ambiguous, surface the interpretations and ask before building. Recommend a simpler approach when you see one. A clarifying question up front beats a wrong implementation.
- **Simplicity first.** Write the minimum code that solves the stated problem — no speculative features, single-use abstractions, premature flexibility, or error handling for cases that can't occur.
- **Surgical changes.** Touch only what the request requires. Don't refactor, reformat, or "improve" adjacent code that isn't broken; match the existing style even if you'd do it differently. Every changed line should trace directly to the request. Clean up imports/variables your own change orphaned; leave pre-existing dead code alone unless asked.
- **Goal-driven execution.** Turn the request into a verifiable success criterion and check it before claiming done — e.g. "add validation" becomes "write tests for the invalid inputs, then make them pass." Don't report success you haven't verified.

## Project Overview

**auth0-server-python** is Auth0's server-side Python SDK for implementing user authentication in Python web applications — interactive login, backchannel login/logout, token management, user linking, and connected accounts.

- **Language:** Python (supports 3.9–3.12)
- **Tech Stack:** authlib, PyJWT + cryptography, httpx (async), Pydantic v2, jwcrypto
- **Package Manager:** Poetry
- **Minimum Platform Version:** Python 3.9
- **Dependencies:** authlib, pyjwt, httpx, pydantic · test: pytest, pytest-asyncio, pytest-mock (full list in `pyproject.toml` — bumping a dep is Ask-First)

## Project Structure

```
auth0-server-python/
├── src/auth0_server_python/
│   ├── auth_server/       # ServerClient (main API) + mfa_client, my_account_client
│   ├── auth_schemes/      # bearer auth scheme
│   ├── auth_types/        # Pydantic models / typed options
│   ├── store/             # AbstractDataStore + StateStore (pluggable session/state storage)
│   ├── encryption/        # encrypt/decrypt for stored state
│   ├── error/             # Auth0Error hierarchy
│   ├── utils/             # PKCE, State, helpers
│   ├── telemetry.py       # builds the Auth0-Client header
│   └── tests/             # pytest suite (async)
├── examples/              # hand-written usage guides (.md, one per use case)
└── pyproject.toml         # Poetry config, deps, pytest options
```

### Key Files

| File | Purpose |
|------|---------|
| `src/auth0_server_python/auth_server/server_client.py` | `ServerClient` — the SDK's public API surface |
| `src/auth0_server_python/store/abstract.py` | `AbstractDataStore` / `StateStore` — storage contract to implement |
| `src/auth0_server_python/error/__init__.py` | `Auth0Error` exception hierarchy |
| `src/auth0_server_python/telemetry.py` | `Auth0-Client` telemetry header |
| `pyproject.toml` | Deps, `ruff`/`pytest` config, coverage settings |

## Boundaries

### ✅ Always Do
- Run `poetry run pytest` and `poetry run ruff check .` before committing.
- Add or update a test for every change (`src/auth0_server_python/tests/`).
- Mark new coroutine tests with `@pytest.mark.asyncio`.
- Raise typed errors from the `Auth0Error` hierarchy (`error/__init__.py`), not bare `Exception`.
- Update `README.md` and the relevant `examples/*.md` in the same PR when you change the public API, configuration options, or supported integration patterns.
- Update `CHANGELOG.md` for user-facing changes.

### ⚠️ Ask First
- Adding a new dependency or bumping one in `pyproject.toml` / `poetry.lock`.
- Changing the public `ServerClient` method signatures or the `AbstractDataStore` contract (breaks downstream implementers).
- Dropping or changing supported Python versions (3.9–3.12 matrix).
- Any breaking change to public behavior — confirm before proceeding.

### 🚫 Never Do
- Commit secrets, client secrets, tokens, or the state-encryption `secret`/`salt`.
- Log access tokens, refresh tokens, ID tokens, or the encryption secret.
- Weaken token/JWT verification (signature, `iss`/`aud`/`exp` checks) to make something pass.
- Skip or delete failing tests without fixing the cause.

## Security Considerations

- **Token handling:** JWTs are verified and decoded via PyJWT/jwcrypto against the tenant's JWKS (fetched and cached from OIDC metadata) — never trust an unverified token.
- **State storage:** session/transaction state is encrypted before it hits the pluggable store (`encryption/encrypt.py`, AES key derived from the configured `secret` + `salt`); `ServerClient` refuses to start without a `secret`.
- **PKCE:** the authorization-code flow uses PKCE (`utils.PKCE`).
- **Secrets stay out of code and logs:** the encryption `secret`, client secret, and tokens are runtime inputs — never hardcode or log them.

---

> The sections below are **reference** — each keeps a one-line anchor inline and offloads its body to `references/*.md` behind a linked pointer. Read a pointer only when the task needs it.

## Commands

```bash
poetry install                 # install deps (with dev group)
poetry run pytest              # run all tests (async) — safe, no credentials
poetry run ruff check .        # lint
```

See [references/commands.md](references/commands.md) for the full list (coverage, single-test, format, build). Read only when you need to run, test, or build something beyond the three above.

## Testing

`poetry run pytest` runs the full suite with coverage (configured in `pyproject.toml`). Tests are async (`pytest-asyncio`) and use `unittest.mock.AsyncMock`/`pytest-mock` — the default suite is unit-only and needs no credentials or live tenant.

See [references/testing.md](references/testing.md) for the async test conventions, mocking approach, and coverage. Read when writing or running tests.

## Code Style

Python formatted and linted with **ruff** (line length 100, target py39). CI runs `ruff check .` and fails on violations — enabled rule sets include `E/W/F/I` (pycodestyle/pyflakes/isort), `B` (bugbear), `UP` (pyupgrade), and `S` (bandit security).

See [references/code-style.md](references/code-style.md) for naming, the async/typed idiom, and good/bad examples. Read when writing or reshaping code.

## Git Workflow

Branch off `main`; run `poetry run pytest` before opening a PR against `main`, following [Auth0's contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md). Every change ships with a test.

See [references/git-workflow.md](references/git-workflow.md) for the full contribution and PR flow. Read when preparing a PR.

## Common Pitfalls

The high-frequency traps: **forgetting `@pytest.mark.asyncio` on coroutine tests**, catching a bare `Exception` instead of an `Auth0Error` subclass, and bandit (`S`) lint failures on crypto/subprocess code.

See [references/pitfalls.md](references/pitfalls.md) for the full list with fixes (JWKS caching, Pydantic v2 model changes, store encryption contract). Read when a test or lint fails unexpectedly.

## Docs Update Rules

Tracked docs: `README.md` (install + getting started) and `examples/*.md` (one hand-written guide per use case — InteractiveLogin, MFA, ConnectedAccounts, UserLinking, etc.). There is no generated API-doc site — the examples are the primary reference.

See [references/docs-update.md](references/docs-update.md) for the code-to-docs mapping (which exported symbol maps to which doc/example). Read when changing the public API or configuration.
