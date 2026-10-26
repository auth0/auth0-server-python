import ast
import os
import sys

from sphinx.ext import intersphinx

sys.path.insert(0, os.path.abspath("../src"))

# -- Project info -------------------------------------------------------

project = "auth0-server-python"
author = "Auth0"
copyright = "2024, Auth0"
with open(os.path.join(os.path.abspath(".."), ".version")) as _version_file:
    release = _version_file.read().strip()

# -- Extensions ---------------------------------------------------------

extensions = [
    "autoapi.extension",
    "sphinx.ext.napoleon",
    "sphinx.ext.linkcode",
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


# -- Links to other projects ---------------------------------------------

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}

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

exclude_patterns = ["_build", "_templates", "Thumbs.db", ".DS_Store"]

def _resolve_root_prefixed(app, env, node, contnode):
    """Resolve annotations that the default lookup misses.

    `auth0_server_python.x.Y` maps to AutoAPI's root-less `x.Y`, and a bare name such
    as `Any` is looked up as `typing.Any`.
    """
    target = node.get("reftarget", "")
    if node.get("refdomain") != "py":
        return None
    prefix = IMPORT_ROOT + "."
    if target.startswith(prefix):
        return env.get_domain("py").resolve_xref(
            env, node.get("refdoc"), app.builder, node["reftype"], target[len(prefix) :], node, contnode
        )
    if "." not in target:
        retargeted = node.copy()
        retargeted["reftarget"] = "typing." + target
        retargeted["reftype"] = "obj"
        return intersphinx.missing_reference(app, env, retargeted, contnode)
    return None


def setup(app):
    app.connect("autoapi-skip-member", autoapi_skip_member)
    app.connect("missing-reference", _resolve_root_prefixed)
