# Git Workflow

## Branches

`main` is the default branch. Observed naming in this repo (pick the shape that matches the work):

| Shape | Example | Use for |
|-------|---------|---------|
| `<feature>-support` | `passkey-support`, `dpop-support`, `myaccount-support` | a new capability |
| `SDK-<ticket>-<slug>` | `SDK-8833-organisations-support` | ticket-tracked work |
| `fix/<slug>` | `fix/mfa-breaking-changes` (#104) | bug fixes |
| `feat/<slug>` | `feat/cte-delegation` | scoped features |
| `docs/<slug>` | `docs/sync-2026-06-30` | docs-only changes |
| `release/<version>` | `release/<the version in .version>` | release prep only — cut by the release flow, not by hand |

## Commits

No commitlint / husky hook exists, so nothing fails CI on message format. History is mixed:
Conventional Commits where a ticket drove it (`feat: enforce upstream IdP session_expiry ceiling
(IPSIE SL1) (#120)`) alongside plain imperative subjects (`Added dpop support for myaccount and
passkeys`). **Prefer Conventional Commits** (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`) for new
work — and keep one logical change per commit.

## Pull requests

`.github/PULL_REQUEST_TEMPLATE.md` is enforced by review, not tooling. It requires four sections:

1. **Changes** — what and why, explicitly listing *endpoints added/deleted/deprecated/changed* and
   *classes and methods added/deleted/deprecated/changed*, plus a usage summary for any new public
   API, and alternatives considered
2. **References** — support ticket, community post, or forum thread
3. **Testing** — how a reviewer verifies it; tick the unit / integration / latest-platform boxes
4. **Checklist** — contribution guidelines, code of conduct, all tests passing

Because the template asks for a method-level inventory, write the PR body from the diff of the public
surface (`ServerClient`, `MyAccountClient`, `MfaClient`, `auth_types`, `error`) — not from a summary
of intent.

## Required checks

From `.github/workflows/`:

- **Build and Test** (`test.yml`) — `pytest` + `ruff check .` across the Python version matrix that workflow defines
- **CodeQL** (`codeql.yml`) — on PR, push to `main`, and a weekly schedule
- **SCA** (`sca_scan.yml`) — Snyk against `requirements.txt`; suppressions live in `.snyk`

`ruff format` is not a check. Reformatting untouched files creates diff noise that CI won't flag but
reviewers will.

## Releases

Version source of truth is `.version`; `.shiprc` points the release tool at it. `pyproject.toml`
carries the same version and must not drift from `.version`. Releases are cut by the release flow
(`publish.yml`, triggered manually, gated on RL scan) — not by an agent editing version files.
`CHANGELOG.md` is written as part of that flow.
