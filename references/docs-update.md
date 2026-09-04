# Docs Update Rules

This repo is a **library/SDK** — its public surface is the exported classes and methods of
`ServerClient`, `MyAccountClient`, `MfaClient`, plus the Pydantic models in `auth_types/` and the
error classes in `error/`. Docs track that surface.

## Tracked docs

| Doc | What it covers | Status |
|-----|----------------|--------|
| `README.md` | Install, `ServerClient` construction, interactive login, custom token exchange, MCD, session expiry, passkeys, My Account, DPoP — each a short section that links out to `examples/` | present |
| `EXAMPLES.md` | — | **not used by design.** This repo puts per-feature guides in `examples/*.md` instead. Add a sample to the matching `examples/` guide; only create `EXAMPLES.md` if the team decides to consolidate. |
| `examples/` | per-feature Markdown guides (not runnable apps), one per flow — see the Feature → guide map below | present |

`CHANGELOG.md` exists but is **not** tracked here — it's written by the release flow, not during a
feature change. Migration guides are likewise not tracked: the filename depends on the target major
at the time of the breaking change.

## New code snippets live in `examples/`, not `README.md`

When you add or change a code sample, put it in the matching `examples/*.md` guide and link to it
from `README.md`'s numbered section for that feature — don't add a new code block to `README.md`
itself. `README.md` already carries some inline snippets from before this rule; don't add more, and
feel free to move one to its guide while you're touching that section.

## When you change code, update these docs

| When this changes | Update these docs |
|-------------------|-------------------|
| A public method on `ServerClient` / `MyAccountClient` / `MfaClient` — added, renamed, or removed | `README.md` if it has a numbered section for the feature, **and** the matching `examples/*.md` guide |
| A method signature (new/removed/renamed parameter, changed default) | every `examples/*.md` code block that calls it |
| `ServerClient.__init__` options (`domain`, `secret`, `authorization_params`, `organization`, `pushed_authorization_requests`, store identifiers) | `README.md` → "Create the Auth0 SDK client" |
| Auth flow behavior (interactive login, callback, passkey ceremony, custom token exchange, backchannel login/logout, DPoP) | `README.md` quick-start section for that flow + the feature's `examples/*.md` |
| `StateStore` / `TransactionStore` abstract contract in `store/abstract.py` (incl. `delete_by_logout_token`) | `examples/ConfigureStore.md` |
| A new or renamed error class or `*ErrorCode` constant in `error/` | the error-handling section of the affected `examples/*.md` |
| A Pydantic model in `auth_types/` used in a documented call | the `examples/*.md` guides constructing it |
| Install name, Python floor, or a new runtime dependency | `README.md` → "Install the SDK" |
| A deprecation (PEP 562 alias in `auth_types`) | `README.md` and the affected `examples/*.md`, stating the replacement |

Update the doc **in the same PR** as the code. The PR template asks for a method-level inventory of
what changed, so the doc diff and the PR body come from the same source.

## A new feature with no guide yet

When a feature has no row in the Feature → guide map below, the change is not complete until you
create one. Add `examples/<Feature>.md` modelled on the closest sibling guide — same section order,
same prose-then-snippet rhythm, same error-handling section — then add its row to that map and link
it from `README.md`'s section for the feature. Name the file after the flow, matching the existing
`PascalCase` filenames. Don't put the feature's only sample in `README.md` instead.

## Feature → guide map

| Feature | Guide |
|---------|-------|
| Redirect login, callback, organizations | `examples/InteractiveLogin.md` |
| Store implementations, `store_options` | `examples/ConfigureStore.md` |
| `get_user` / `get_session` / `get_access_token`, session expiry | `examples/RetrievingData.md` |
| MFA (`ServerClient.mfa`, `MfaClient`) | `examples/MFA.md` |
| Passkey ceremonies + DPoP-bound passkey tokens | `examples/Passkeys.md` |
| My Account authentication methods + DPoP | `examples/MyAccountAuthenticationMethods.md` |
| Connected accounts / Token Vault | `examples/ConnectedAccounts.md` |
| RFC 8693 token exchange | `examples/CustomTokenExchange.md` |
| CIBA | `examples/ClientInitiatedBackChannelLogin.md` |
| MCD domain resolver | `examples/MultipleCustomDomains.md` |
| Account linking / unlinking | `examples/UserLinking.md` |
| Passwordless email/SMS OTP + magic link | `examples/Passwordless.md` |
| Enterprise Connect embedded login (`enterprise_connect`, `start_enterprise_login`, `is_federated_domain`) | `examples/EnterpriseConnect.md` |
