# AI Agent Guidelines for auth0-server-python

This document provides context and guidelines for AI coding assistants working with the auth0-server-python codebase.

## Your Role

You are a Python SDK engineer on auth0-server-python — Auth0's framework-agnostic server-side authentication SDK. You work in async OIDC flows, Pydantic-typed models, and pluggable session/transaction stores that integrators supply.

---

## Working Principles

Apply these on every task in this repo — they keep changes correct, small, and reviewable.

- **Think before coding.** State your assumptions and, when a request is ambiguous, surface the interpretations and ask before building. Recommend a simpler approach when you see one. A clarifying question up front beats a wrong implementation.
- **Simplicity first.** Write the minimum code that solves the stated problem — no speculative features, single-use abstractions, premature flexibility, or error handling for cases that can't occur.
- **Surgical changes.** Touch only what the request requires. Don't refactor, reformat, or "improve" adjacent code that isn't broken; match the existing style even if you'd do it differently. Every changed line should trace directly to the request. Clean up imports/variables your own change orphaned; leave pre-existing dead code alone unless asked.
- **Goal-driven execution.** Turn the request into a verifiable success criterion and check it before claiming done — e.g. "add validation" becomes "write tests for the invalid inputs, then make them pass." Don't report success you haven't verified.

---

## Project Structure

**auth0-server-python** is the server-side (confidential client) SDK that framework wrappers such as `auth0-fastapi` build on.

```
src/auth0_server_python/
├── auth_server/
│   ├── server_client.py        # ServerClient — main entry point; login, session, token, passkey, CTE flows
│   ├── mfa_client.py           # MfaClient — MFA API; exposed via ServerClient.mfa
│   └── my_account_client.py    # MyAccountClient — My Account API (stateless; takes a user token per call)
├── auth_schemes/
│   ├── bearer_auth.py          # BearerAuth — httpx.Auth strategy
│   └── dpop_auth.py            # DPoPAuth — RFC 9449 proofs, nonce retry, EC P-256 enforcement
├── auth_types/__init__.py      # All public Pydantic models + Literal type aliases
├── error/__init__.py           # Auth0Error hierarchy + *ErrorCode constant classes
├── store/abstract.py           # StateStore / TransactionStore ABCs integrators implement
├── encryption/encrypt.py       # JWE encrypt/decrypt (HKDF-SHA256 → A256CBC-HS512)
├── utils/helpers.py            # PKCE, State, URL helpers; org-claim + domain-resolver validation
├── telemetry.py                # Auth0-Client header construction
└── tests/                      # pytest suite, one test_<module>.py per module
examples/                       # 11 per-feature Markdown guides (not runnable apps)
references/                     # Agent reference docs (this file's offloaded sections)
```

---

## Boundaries

### ✅ Always Do

- Run `poetry run pytest` and `poetry run ruff check .` before committing — both gate CI.
- Add tests for new functionality, and mark async tests `@pytest.mark.asyncio` — see Common Pitfalls for why.
- Raise a typed error from `error/` with a stable `code`, and re-raise the SDK's own errors untouched inside a catch-all — never return `None` or a bare `dict` to signal failure.
- Return Pydantic models from `auth_types/`, validated via `model_validate` — never leak an unvalidated response `dict` through the public API.
- Resolve the domain through `await self._resolve_current_domain(store_options)` and thread `store_options` through every new public flow method — reading `self._domain` breaks MCD deployments and cookie-backed stores.
- Issue HTTP through `self._get_http_client()` so the `Auth0-Client` telemetry header is attached. When adding a **new outbound request path to Auth0**, route it through the existing `src/auth0_server_python/telemetry.py` mechanism rather than constructing a client or headers by hand.
- Attach credentials with `BearerAuth` / `DPoPAuth` from `auth_schemes/`, not by setting `Authorization` inline.
- Keep `Optional[X]` / `Union[...]` typing and `target-version = "py39"`-compatible syntax — the 3.9 CI leg fails on 3.10+ constructs.
- Update `README.md` and the matching `examples/*.md` guide in the same PR when changing the public API, configuration options, or supported integration patterns.
- Put new code snippets in the matching `examples/*.md` guide and link to it from `README.md` — don't add another code block to `README.md`.
- Keep `.version` and `pyproject.toml`'s `version` in sync when either is touched.
- Preserve existing declaration order and the `# ==== SECTION ====` banners; insert new methods into the matching section. In a file without banners, group a new method/class/function with the related code it belongs to, or append it at the end — never insert it at an arbitrary position.

### ⚠️ Ask First

- **Any breaking change — always ask first.** Never make one on your own initiative: a renamed/removed public method, a changed signature or default, a tightened model field, a new required constructor argument, or a raised Python floor.
- Adding, removing, or bumping a dependency (`pyproject.toml` + `poetry.lock` + `requirements.txt` must move together — Snyk SCA installs from `requirements.txt`).
- Changing security-relevant code: token handling, `encryption/encrypt.py`, DPoP proof construction, PKCE, `state`/`nonce` handling, issuer or org-claim validation, session-expiry enforcement.
- Modifying the `StateStore` / `TransactionStore` contract in `store/abstract.py`.
- Changing CI/CD (`.github/workflows/`), `.ruff.toml` rule selection, or `.snyk` suppressions.
- Changing the session or transaction storage format, or the store identifier defaults (`_a0_session`, `_a0_tx`).
- Deprecating a public name — use the PEP 562 `__getattr__` alias pattern in `auth_types/`; don't delete it.

### 🚫 Never Do

- Commit secrets, API keys, tokens, or a real Auth0 tenant domain. Test fixtures use `<client_id>`-style placeholders and `auth0.local`.
- Log, `print`, or include in an error message any token, `code`, `code_verifier`, `client_secret`, DPoP private key, or full response body. There is no logger in the SDK — don't introduce one that emits these.
- Fail open. A validation, resolver, JWKS, or token-endpoint failure must raise, never fall through to a permissive default (no default domain, no "assume valid").
- Validate `state` by comparing strings. `complete_interactive_login` looks the transaction up by `{transaction_identifier}:{state}` and raises `MissingTransactionError` on a miss — that store lookup *is* the binding. If you ever add a secret-to-secret comparison, use `hmac.compare_digest`, never `==`.
- Run `ruff format .` repo-wide — it is not a CI gate and the tree is not format-clean (13 files would change). Format only lines you touched.
- Remove or `skip` a failing test instead of fixing it, or weaken an assertion to make it pass.
- Hand-edit `poetry.lock`, `coverage.xml`, `CHANGELOG.md` (release flow owns it), or anything in `dist/`, `.venv/`, `__pycache__/`, `.pytest_cache/`, `.ruff_cache/`.
- Break backward compatibility without asking first (see Ask First) and getting explicit approval.

---

## Security Considerations

This SDK is a **confidential client**: it holds a real client secret server-side and the browser never sees a token.

- **Tokens are server-side only.** Access, refresh, and ID tokens live in the integrator's `StateStore`; the browser holds only an opaque session reference. Never add a public accessor that hands a raw refresh token to the caller's browser layer.
- **Store payloads are encrypted.** `encryption/encrypt.py` derives a key with HKDF-SHA256 from the integrator's `secret` salted with the record identifier, then produces a JWE (`alg: dir`, `enc: A256CBC-HS512`). `secret` is required at construction — `ServerClient` raises `MissingRequiredArgumentError` without it, and must keep failing closed rather than storing plaintext.
- **PKCE is always on** for the authorization-code flow (`utils/helpers.py` `PKCE`, `secrets`-backed), even though this is a confidential client. `state` and `nonce` are generated per transaction and validated at callback.
- **DPoP (RFC 9449)** is supported for passkey sign-in and the My Account authentication-methods/factors calls. Keys must be EC P-256/ES256 (`_validate_dpop_key` rejects anything else); resource proofs carry `ath`, token-endpoint proofs deliberately do not; a `401` + `DPoP-Nonce` triggers exactly one retry.
- **Token and claim validation is mandatory.** ID-token issuer validation (`IssuerValidationError`), organization `org_id`/`org_name` claim validation (exact for `org_`-prefixed IDs, NFC-normalized case-insensitive for names), and the upstream-IdP `session_expiry` ceiling (30s skew leeway) all fail closed. Don't add a bypass flag.
- **Backchannel logout** matches on `sid` **or** `sub` per the OIDC spec, and compares the token `iss` against the session's stored domain before deleting — this is what prevents cross-domain session deletion in MCD deployments.
- **Secret handling.** `AUTH0_SECRET` and the client secret come from the integrator's environment/secrets manager; the SDK never reads them from disk and must never write them anywhere. `S105`/`S106` are ignored in `.ruff.toml` for kwarg names — that suppression is not permission to hardcode a value.
- **Scanning:** CodeQL (`codeql.yml`) and Snyk SCA (`sca_scan.yml`) run on every PR; ruff's bandit rules (`S`) run in `ruff check .`. Report vulnerabilities via Auth0's Responsible Disclosure Program, never a public issue.

---

> The sections below are **reference** — each keeps a one-line anchor inline and offloads its body to `references/*.md`.

## Commands

```bash
poetry install                 # setup
poetry run pytest              # full suite (coverage flags come from pyproject.toml)
poetry run ruff check .        # the lint gate in CI
poetry build                   # sdist + wheel
```

See [references/commands.md](references/commands.md) for the exact CI invocations, single-file/single-test runs, format and clean commands, and what deliberately doesn't exist here (no typecheck, no live-test tier). Read it when you need to run, build, or test something.

## Testing

pytest + pytest-asyncio in `src/auth0_server_python/tests/` (one `test_<module>.py` per module); the default `poetry run pytest` suite is mock-based and needs no credentials. Async tests require an explicit `@pytest.mark.asyncio`.

See [references/testing.md](references/testing.md) for naming, class-grouping conventions, the factory-helper pattern, mocking approach, and coverage setup. Read it before writing or restructuring tests.

## Code Style

Config is `.ruff.toml` at the repo root. CI-enforced: ruff's `E,W,F,I,B,C4,UP,S,PLC0415` rule sets — so **isort-ordered imports** (stdlib → third-party → local), **no imports inside functions** (`PLC0415`), and **bandit security rules** are hard gates. `E501` is ignored, so the `line-length = 100` is not enforced. `snake_case` methods, `PascalCase` classes, `_`-prefixed internals.

See [references/code-style.md](references/code-style.md) for the good/bad method examples and the dominant patterns (generic store client, `httpx.Auth` strategies, Pydantic wire contracts, PEP 562 deprecation aliases). Read it before adding a public method or a new module.

## Git Workflow

Conventional Commits preferred (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`) — nothing enforces it, history is mixed. `.github/PULL_REQUEST_TEMPLATE.md` requires a method-level inventory of what changed.

See [references/git-workflow.md](references/git-workflow.md) for branch naming, the full PR template requirements, and required checks. Read it when opening a PR or naming a branch.

## Common Pitfalls

The three that bite most often: the **Python 3.9 floor** (no `X | None`), **`ruff format` is not a CI gate** so don't reformat the tree, and a **missing `@pytest.mark.asyncio`** skips an async test with a warning instead of running it.

See [references/pitfalls.md](references/pitfalls.md) for all eight, including the MCD domain-resolver trap, the `store_options` threading requirement, and the `Literal`-vs-`str` typing rule. Read it when a change touches HTTP, domains, or type annotations.

## Docs Update Rules

> A PR that adds or changes public API, configuration, or integration patterns is **not complete** until the docs move with it.

Note: there is **no `EXAMPLES.md`** in this repo — per-feature guides live in `examples/*.md` instead. `CHANGELOG.md` is owned by the release flow, not by feature work.

See [references/docs-update.md](references/docs-update.md) for the tracked-docs inventory, the code-to-docs mapping table, and the feature → guide map. Read it whenever you change a public method, signature, config option, or error type.
