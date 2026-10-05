import os
import sys

sys.path.insert(0, os.path.abspath("../src"))

# -- Project info -------------------------------------------------------

project = "auth0-server-python"
author = "Auth0"
copyright = "2024, Auth0"
release = "1.0.0b18"

# -- Extensions ---------------------------------------------------------

extensions = [
    "autoapi.extension",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
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

# -- Intersphinx --------------------------------------------------------

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "pydantic": ("https://docs.pydantic.dev/latest/", None),
}

# -- HTML output --------------------------------------------------------

html_show_sphinx = False
html_show_copyright = False
html_theme = "furo"
html_title = "auth0-server-python"
html_static_path = ["_static"]
html_css_files = ["auth0.css"]
html_theme_options = {
    "sidebar_hide_name": False,
    "navigation_with_keys": True,
    "light_css_variables": {
        "color-brand-primary": "#9921FE",
        "color-brand-content": "#9921FE",
    },
    "dark_css_variables": {
        "color-brand-primary": "#BC6DFF",
        "color-brand-content": "#BC6DFF",
    },
}

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

# -- Mintlify / docs-v2 post-processing ---------------------------------

DOCS_V2_DIRECTORY = "docs/sdk/python/server"

TITLE_OVERRIDES = {
    "reference/auth_server/anonymous/client/index": "Anonymous Client",
}

REMOVE_PAGES = []

DOCS_V2_NAVIGATION = [
    {
        "group": "Auth Server",
        "pages": [
            f"{DOCS_V2_DIRECTORY}/reference/auth_server/server_client/index",
            f"{DOCS_V2_DIRECTORY}/reference/auth_server/anonymous/client/index",
            f"{DOCS_V2_DIRECTORY}/reference/auth_server/mfa_client/index",
            f"{DOCS_V2_DIRECTORY}/reference/auth_server/my_account_client/index",
            f"{DOCS_V2_DIRECTORY}/reference/auth_server/passwordless_client/index",
        ],
    },
    {
        "group": "Auth Schemes",
        "pages": [
            f"{DOCS_V2_DIRECTORY}/reference/auth_schemes/bearer_auth/index",
            f"{DOCS_V2_DIRECTORY}/reference/auth_schemes/dpop_auth/index",
            f"{DOCS_V2_DIRECTORY}/reference/auth_schemes/client_assertion/index",
        ],
    },
    {
        "group": "Types",
        "pages": [f"{DOCS_V2_DIRECTORY}/reference/auth_types/index"],
    },
    {
        "group": "Store",
        "pages": [
            f"{DOCS_V2_DIRECTORY}/reference/store/abstractdatastore/index",
            f"{DOCS_V2_DIRECTORY}/reference/store/statestore/index",
            f"{DOCS_V2_DIRECTORY}/reference/store/transactionstore/index",
        ],
    },
    {
        "group": "Encryption",
        "pages": [f"{DOCS_V2_DIRECTORY}/reference/encryption/encrypt/index"],
    },
    {
        "group": "Errors",
        "pages": [f"{DOCS_V2_DIRECTORY}/reference/error/index"],
    },
    {
        "group": "Utilities",
        "pages": [
            f"{DOCS_V2_DIRECTORY}/reference/utils/helpers/index",
            f"{DOCS_V2_DIRECTORY}/reference/telemetry/index",
        ],
    },
]


def _postprocess_json_build(app, exception):
    import json
    if exception or app.builder.name != "json":
        return

    out = app.outdir

    for page_path, title in TITLE_OVERRIDES.items():
        fpath = os.path.join(out, page_path + ".fjson")
        if not os.path.exists(fpath):
            continue
        with open(fpath) as f:
            data = json.load(f)
        data["title"] = title
        with open(fpath, "w") as f:
            json.dump(data, f, indent=2)

    for page_path in REMOVE_PAGES:
        fpath = os.path.join(out, page_path + ".fjson")
        if os.path.exists(fpath):
            os.remove(fpath)

    nav_path = os.path.join(out, "navigation.json")
    with open(nav_path, "w") as f:
        json.dump({"pages": DOCS_V2_NAVIGATION}, f, indent=2)

    print(f"[auth0-server-python] Wrote {nav_path}")


def setup(app):
    app.connect("autoapi-skip-member", autoapi_skip_member)
    app.connect("build-finished", _postprocess_json_build)
