import ast
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
    "sphinx.ext.linkcode",
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
]
autoapi_member_order = "groupwise"
autoapi_keep_files = True
autoapi_template_dir = "_templates/autoapi"
autoapi_python_class_content = "class"

# Top-level import package, shown in each module's import block.
IMPORT_ROOT = "auth0_server_python"


def autoapi_prepare_jinja_env(jinja_env):
    jinja_env.globals["import_root"] = IMPORT_ROOT



def autoapi_skip_member(app, what, name, obj, skip, options):
    if what == "class" and name.endswith(".Config"):
        return True
    return skip


# -- Signatures ---------------------------------------------------------

# Show `Name(...)` not `module.Name(...)`. The import block gives the full path.
add_module_names = False

# -- Source links -------------------------------------------------------

REPO_ROOT = os.path.abspath("..")
GITHUB_BLOB_URL = "https://github.com/auth0/auth0-server-python/blob/main"


def _definition_line(path, fullname):
    """Line where ``fullname`` (``Class.method``) is defined as a class or function, or None."""
    with open(path) as f:
        nodes = ast.parse(f.read()).body
    node = None
    for name in fullname.split("."):
        node = next(
            (
                n
                for n in nodes
                if isinstance(n, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
                and n.name == name
            ),
            None,
        )
        if node is None:
            return None
        nodes = node.body
    return node.lineno if node else None


def linkcode_resolve(domain, info):
    if domain != "py" or not info.get("module"):
        return None
    base = os.path.join(REPO_ROOT, "src", IMPORT_ROOT, *info["module"].split("."))
    path = base + ".py" if os.path.isfile(base + ".py") else os.path.join(base, "__init__.py")
    if not os.path.isfile(path):
        return None
    # Attributes and fields have no definition of their own, so they get no link.
    line = _definition_line(path, info.get("fullname", ""))
    if line is None:
        return None
    return f"{GITHUB_BLOB_URL}/{os.path.relpath(path, REPO_ROOT)}#L{line}"


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
mintlify_github_blob_url = GITHUB_BLOB_URL
mintlify_guides_root = REPO_ROOT

mintlify_remove_pages = []

# -- Guides (README, CONTRIBUTING, examples/*.md) -----------------------

EXAMPLE_PAGES = sorted(
    f[:-3] for f in os.listdir(os.path.join(mintlify_guides_root, "examples")) if f.endswith(".md")
)

# Output page -> (Markdown source relative to the repo root, fixed title or "").
mintlify_guides = {
    "overview": ("README.md", "Overview"),
    "CONTRIBUTING": ("CONTRIBUTING.md", ""),
    **{f"examples/{name}": (f"examples/{name}.md", "") for name in EXAMPLE_PAGES},
}

# -- Navigation ---------------------------------------------------------

# Guides starts folded and API Reference starts open. Nested groups are
# what the docs site renders as foldable. "{reference}" is replaced by the
# API reference groups, which are built from the generated pages.
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
                "pages": ["{reference}"],
            },
            f"{SITE_DIR}/CONTRIBUTING",
        ],
    },
]


def setup(app):
    app.connect("autoapi-skip-member", autoapi_skip_member)
