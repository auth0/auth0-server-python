import os
import sys

sys.path.insert(0, os.path.abspath("../src"))
sys.path.insert(0, os.path.abspath("."))

# -- Project info -------------------------------------------------------

project = "auth0-server-python"
author = "Auth0"
copyright = "2024, Auth0"
release = "1.0.0b18"

# -- Extensions ---------------------------------------------------------

extensions = [
    "autoapi.extension",
    "sphinx.ext.napoleon",
    "mintlify_export",
]

# -- AutoAPI ------------------------------------------------------------

autoapi_dirs = ["../src"]
autoapi_type = "python"
autoapi_root = "reference"
autoapi_ignore = ["**/tests/**", "**/test_*.py"]

autoapi_options = [
    "members",
    "undoc-members",
    "show-inheritance",
    "show-module-summary",
]
autoapi_member_order = "groupwise"
autoapi_keep_files = True
autoapi_template_dir = "_templates/autoapi"
autoapi_python_class_content = "class"


def autoapi_skip_member(app, what, name, obj, skip, options):
    if what == "class" and name.endswith(".Config"):
        return True
    return skip


# -- Napoleon (docstring style) -----------------------------------------

napoleon_google_docstring = True
napoleon_use_param = True
napoleon_use_rtype = True
napoleon_preprocess_types = True

# -- General ------------------------------------------------------------

templates_path = ["_templates"]

exclude_patterns = [
    "_build",
    "_templates",
    "Thumbs.db",
    ".DS_Store",
    "reference/index.rst",
    "reference/auth_schemes/index.rst",
    "reference/auth_server/index.rst",
    "reference/auth_server/anonymous/index.rst",
    "reference/auth_server/anonymous/helpers/index.rst",
    "reference/encryption/index.rst",
    "reference/store/index.rst",
    "reference/utils/index.rst",
]

# -- Docs site export (see mintlify_export/) ---------------------------

SITE_DIR = "docs/sdk/python/server"

mintlify_site_dir = SITE_DIR
mintlify_github_blob_url = "https://github.com/auth0/auth0-server-python/blob/main"
mintlify_guides_root = os.path.abspath("..")

mintlify_title_overrides = {
    "reference/auth_server/anonymous/client/index": "Anonymous Client",
}

mintlify_remove_pages = []

# Split a single autoapi module page into per-class pages.
# Keys are source page paths (no extension); values are lists of class descriptors.
mintlify_class_splits = {
    "reference/store/abstract/index": [
        {
            "class_id": "store.abstract.AbstractDataStore",
            "title": "AbstractDataStore",
            "output_path": "reference/store/abstractdatastore/index",
        },
        {
            "class_id": "store.abstract.StateStore",
            "title": "StateStore",
            "output_path": "reference/store/statestore/index",
        },
        {
            "class_id": "store.abstract.TransactionStore",
            "title": "TransactionStore",
            "output_path": "reference/store/transactionstore/index",
        },
    ],
}

# -- Guides (README, CONTRIBUTING, examples/*.md) -----------------------

EXAMPLE_PAGES = sorted(
    f[:-3] for f in os.listdir(os.path.join(mintlify_guides_root, "examples")) if f.endswith(".md")
)

# Output page -> (Markdown source relative to the repo root, fixed title or "").
mintlify_guides = {
    "overview": ("README.md", "auth0-server-python"),
    "CONTRIBUTING": ("CONTRIBUTING.md", ""),
    **{f"examples/{name}": (f"examples/{name}.md", "") for name in EXAMPLE_PAGES},
}

# -- Navigation ---------------------------------------------------------

API_REFERENCE_GROUPS = [
    {
        "group": "Auth Server",
        "pages": [
            f"{SITE_DIR}/reference/auth_server/server_client/index",
            f"{SITE_DIR}/reference/auth_server/anonymous/client/index",
            f"{SITE_DIR}/reference/auth_server/mfa_client/index",
            f"{SITE_DIR}/reference/auth_server/my_account_client/index",
            f"{SITE_DIR}/reference/auth_server/passwordless_client/index",
        ],
    },
    {
        "group": "Auth Schemes",
        "pages": [
            f"{SITE_DIR}/reference/auth_schemes/bearer_auth/index",
            f"{SITE_DIR}/reference/auth_schemes/dpop_auth/index",
            f"{SITE_DIR}/reference/auth_schemes/client_assertion/index",
        ],
    },
    {
        "group": "Types",
        "pages": [f"{SITE_DIR}/reference/auth_types/index"],
    },
    {
        "group": "Store",
        "pages": [
            f"{SITE_DIR}/reference/store/abstractdatastore/index",
            f"{SITE_DIR}/reference/store/statestore/index",
            f"{SITE_DIR}/reference/store/transactionstore/index",
        ],
    },
    {
        "group": "Encryption",
        "pages": [f"{SITE_DIR}/reference/encryption/encrypt/index"],
    },
    {
        "group": "Errors",
        "pages": [f"{SITE_DIR}/reference/error/index"],
    },
    {
        "group": "Utilities",
        "pages": [
            f"{SITE_DIR}/reference/utils/helpers/index",
            f"{SITE_DIR}/reference/telemetry/index",
        ],
    },
]

# Guides starts folded and API Reference starts open. Nested groups are
# what the docs site renders as foldable.
mintlify_navigation = [
    {
        "group": "auth0-server-python",
        "pages": [
            f"{SITE_DIR}/overview",
            {
                "group": "Guides",
                "expanded": False,
                "pages": [f"{SITE_DIR}/examples/{name}" for name in EXAMPLE_PAGES],
            },
            {
                "group": "API Reference",
                "expanded": True,
                "pages": [{**group, "expanded": True} for group in API_REFERENCE_GROUPS],
            },
            f"{SITE_DIR}/CONTRIBUTING",
        ],
    },
]


def setup(app):
    app.connect("autoapi-skip-member", autoapi_skip_member)
