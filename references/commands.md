# Commands

Canonical source: `pyproject.toml` (Poetry) and `.github/workflows/test.yml`.

## Everyday

```bash
poetry install                 # install deps (dev group included)
poetry run pytest              # run all tests (async), with coverage per pyproject.toml
poetry run ruff check .        # lint
```

## Coverage & single test

```bash
# Coverage is on by default (addopts in pyproject.toml): term-missing + xml
poetry run pytest -v --cov=auth0_server_python --cov-report=term-missing --cov-report=xml

# Run a single test file or test
poetry run pytest src/auth0_server_python/tests/test_server_client.py
poetry run pytest src/auth0_server_python/tests/test_server_client.py::test_init_no_secret_raises
```

## Lint autofix & build

```bash
poetry run ruff check . --fix  # apply autofixable lint fixes
poetry run ruff format .       # format
poetry build                   # build the package (sdist + wheel)
```

CI (`test.yml`) runs `poetry run pytest` across Python 3.9–3.12 and `poetry run ruff check .`.
