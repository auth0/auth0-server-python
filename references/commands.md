# Command Reference

Every command below maps to a real step in `.github/workflows/test.yml`, a `pyproject.toml` task, or `CONTRIBUTING.md`.

## Setup

```bash
poetry install                      # install runtime + dev dependencies
poetry install --no-interaction     # CI form (test.yml)
```

CI pins Poetry to `2.2.1` (`snok/install-poetry@v1`) with `virtualenvs-in-project: true`.

## Test

```bash
poetry run pytest                                   # full suite (CONTRIBUTING.md)
poetry run pytest -v --cov=auth0_server_python \
  --cov-report=term-missing --cov-report=xml        # exact CI command (test.yml)
poetry run pytest src/auth0_server_python/tests/test_mfa_client.py   # one file
poetry run pytest -k test_start_interactive_login                     # one test by name
poetry run pytest --no-cov -q                       # skip coverage for a fast loop
```

Coverage flags are already in `pyproject.toml` `[tool.pytest.ini_options] addopts`, so a bare
`poetry run pytest` also produces `coverage.xml` and a term-missing report.

## Lint

```bash
poetry run ruff check .        # the only lint gate in CI (test.yml)
poetry run ruff check . --fix  # auto-fix the fixable subset
```

## Format

```bash
poetry run ruff format --check .   # reports 13 already-unformatted files — see references/pitfalls.md
```

`ruff format` is **not** a CI gate and the tree is not format-clean. Never run `ruff format .`
repo-wide; format only the lines you touched.

## Build

```bash
poetry build   # sdist + wheel into dist/ (CONTRIBUTING.md, publish.yml)
```

## Clean

```bash
rm -rf dist/ .pytest_cache/ .ruff_cache/ coverage.xml
find . -name __pycache__ -type d -prune -exec rm -rf {} +
```

## Not available here

- **No typecheck command** — mypy/pyright are not in `pyproject.toml` and no CI step runs them.
  Types are enforced at runtime by Pydantic models in `auth_types/`, not by a static checker.
- **No integration/e2e tier** — the detected suite runs entirely on mocks; nothing in
  `pyproject.toml` or CI reads Auth0 tenant credentials.

## CI matrix

`test.yml` runs the test + lint steps on Python 3.9, 3.10, 3.11, and 3.12. Anything that
depends on a 3.10+ syntax or stdlib feature breaks the 3.9 leg — see `references/pitfalls.md`.
