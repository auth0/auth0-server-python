# Git Workflow

Follows [Auth0's general contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md) (referenced from `CONTRIBUTING.md`).

## Flow

1. Branch off `main` with a short, descriptive name.
2. `poetry install` to set up the environment.
3. Make the change; add/update a test (every change ships with a test).
4. Run `poetry run pytest` and `poetry run ruff check .` locally.
5. Update `CHANGELOG.md` for user-facing changes.
6. Open a PR against `main` and complete the PR template.

## CI gates

`test.yml` must pass: `poetry run pytest` across Python 3.9–3.12 and `poetry run ruff check .`. CodeQL and SCA/Snyk scans also run.

## Releases

Publishing is automated via `publish.yml` (Poetry build + dynamic versioning); the version lives in `.version` / `pyproject.toml`. Don't hand-cut a release or bump the version as part of a feature PR.
