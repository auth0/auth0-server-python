# Common Pitfalls

- **Forgetting `@pytest.mark.asyncio`.** The SDK is async; a coroutine test without the marker is silently skipped or errors. Mark every `async def test_*`.
- **Missing `await`.** `ServerClient` methods and the store contract are coroutines — a forgotten `await` returns a coroutine object, not the result. Bugbear (`B`) catches some cases, not all.
- **Bare `except Exception`.** Catch/raise the specific `Auth0Error` subclass (`ApiError`, `MissingTransactionError`, `MissingRequiredArgumentError`, …) so callers can branch on `.code`. Bandit/bugbear will also flag broad excepts.
- **Bandit (`S`) lint failures.** The `S` rule set scans crypto and subprocess usage. When working in `encryption/` or JWT verification, expect bandit to scrutinize it — don't silence a finding by weakening the crypto.
- **Weakening JWT/JWKS verification.** Tokens are verified against the tenant's cached JWKS with issuer/audience/expiry checks. Don't disable a check to make a test pass; fix the token/fixture instead.
- **Constructing `ServerClient` without a `secret`.** It raises `MissingRequiredArgumentError("secret")` by design — the secret drives state encryption. Pass one (a test value) in tests.
- **Pydantic v2 semantics.** Models are Pydantic v2 (`auth_types/`); use v2 APIs (`model_dump`, `model_validate`) — not the removed v1 methods.
- **Reusing OIDC/JWKS fetches.** Metadata and JWKS are cached on the client; call the cached helpers rather than adding a fresh network fetch.
