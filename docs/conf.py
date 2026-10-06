import json
import os
import re
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

# -- Mintlify post-processing ---------------------------------

DOCS_V2_DIRECTORY = "docs/sdk/python/server"

TITLE_OVERRIDES = {
    "reference/auth_server/anonymous/client/index": "Anonymous Client",
}

REMOVE_PAGES = []

# Split a single autoapi module page into per-class pages.
# Keys are source page paths (no .fjson); values are lists of class descriptors.
STORE_CLASS_SPLITS = {
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


def _split_class_blocks(body):
    """Return a list of HTML strings, one per <dl class="py class"> block."""
    starts = [m.start() for m in re.finditer(r'<dl class="py class">', body)]
    if not starts:
        return []
    return [
        body[start : (starts[i + 1] if i + 1 < len(starts) else len(body))]
        for i, start in enumerate(starts)
    ]

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

    for source_path, classes in STORE_CLASS_SPLITS.items():
        source_fpath = os.path.join(out, source_path + ".fjson")
        if not os.path.exists(source_fpath):
            continue
        with open(source_fpath) as f:
            source_data = json.load(f)
        blocks = _split_class_blocks(source_data["body"])
        for i, cls in enumerate(classes):
            if i >= len(blocks):
                continue
            page_data = dict(source_data)
            page_data["title"] = cls["title"]
            page_data["body"] = (
                f'<section id="{cls["title"].lower()}">'
                f"<h1>{cls['title']}</h1>"
                f"{blocks[i]}"
                f"</section>"
            )
            page_data["current_page_name"] = cls["output_path"]
            page_data["toc"] = ""
            out_fpath = os.path.join(out, cls["output_path"] + ".fjson")
            os.makedirs(os.path.dirname(out_fpath), exist_ok=True)
            with open(out_fpath, "w") as f:
                json.dump(page_data, f, indent=2)
        os.remove(source_fpath)

    nav_path = os.path.join(out, "navigation.json")
    with open(nav_path, "w") as f:
        json.dump({"pages": DOCS_V2_NAVIGATION}, f, indent=2)

    print(f"[auth0-server-python] Wrote {nav_path}")


def setup(app):
    app.connect("autoapi-skip-member", autoapi_skip_member)
    app.connect("build-finished", _postprocess_json_build)
