import json
import os
import posixpath
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

# -- Guides (README, CONTRIBUTING, examples/*.md) -----------------------
# Converted straight from Markdown to MDX at build time, so they never pass
# through Sphinx and are never duplicated.

_HERE = os.path.dirname(__file__)
REPO_ROOT = os.path.join(_HERE, "..")
EXAMPLES_SRC = os.path.join(REPO_ROOT, "examples")

EXAMPLE_PAGES = sorted(
    f[:-3] for f in os.listdir(EXAMPLES_SRC) if f.endswith(".md")
)


API_REFERENCE_GROUPS = [
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

# Guides starts folded and API Reference starts open. Nested groups are
# what the docs site renders as foldable.
DOCS_V2_NAVIGATION = [
    {
        "group": "auth0-server-python",
        "pages": [
            f"{DOCS_V2_DIRECTORY}/overview",
            {
                "group": "Guides",
                "expanded": False,
                "pages": [
                    f"{DOCS_V2_DIRECTORY}/examples/{name}" for name in EXAMPLE_PAGES
                ],
            },
            {
                "group": "API Reference",
                "expanded": True,
                "pages": [{**group, "expanded": True} for group in API_REFERENCE_GROUPS],
            },
            f"{DOCS_V2_DIRECTORY}/CONTRIBUTING",
        ],
    },
]


GITHUB_BLOB_URL = "https://github.com/auth0/auth0-server-python/blob/main"

OVERVIEW_TITLE = "auth0-server-python"

# GitHub alert type -> callout component.
ALERT_COMPONENTS = {
    "NOTE": "Note",
    "TIP": "Tip",
    "IMPORTANT": "Warning",
    "WARNING": "Warning",
    "CAUTION": "Warning",
}

# Output page -> (Markdown source relative to the repo root, fixed title or "").
GUIDE_PAGES = {
    "overview": ("README.md", OVERVIEW_TITLE),
    "CONTRIBUTING": ("CONTRIBUTING.md", ""),
    **{f"examples/{name}": (f"examples/{name}.md", "") for name in EXAMPLE_PAGES},
}


def _toggles_fence(line):
    return re.match(r"[>\s]*(```|~~~)", line) is not None


def _convert_alerts(lines):
    out, in_fence, i = [], False, 0
    while i < len(lines):
        line = lines[i]
        if _toggles_fence(line):
            in_fence = not in_fence
        match = None if in_fence else re.match(r">\s*\[!(\w+)\]\s*(.*)$", line)
        if not match or match.group(1) not in ALERT_COMPONENTS:
            out.append(line)
            i += 1
            continue
        tag = ALERT_COMPONENTS[match.group(1)]
        body = [match.group(2).strip()] if match.group(2).strip() else []
        i += 1
        while i < len(lines) and lines[i].startswith(">"):
            body.append(re.sub(r"^>\s?", "", lines[i]).rstrip())
            i += 1
        out += [f"<{tag}>", "", *body, "", f"</{tag}>"]
    return out


def _link_to_github(lines, source_dir):
    def repl(match):
        href = match.group(1)
        if re.match(r"([a-z][a-z0-9+.-]*:|#|/)", href, re.IGNORECASE):
            return match.group(0)
        path, sep, anchor = href.partition("#")
        target = posixpath.normpath(posixpath.join(source_dir, path))
        return f"]({GITHUB_BLOB_URL}/{target}{sep}{anchor})"

    out, in_fence = [], False
    for line in lines:
        if _toggles_fence(line):
            in_fence = not in_fence
            out.append(line)
        else:
            out.append(line if in_fence else re.sub(r"\]\(([^)\s]+)\)", repl, line))
    return out


def _markdown_to_mdx(md, title, source_dir):
    # The logo block uses <picture>/<source>, which MDX cannot parse.
    md = re.sub(
        r'<p align="center">\s*<picture>.*?</picture>\s*</p>\s*', "", md, flags=re.DOTALL
    )
    lines = md.split("\n")

    first = next((i for i, line in enumerate(lines) if line.strip()), None)
    if first is not None and re.match(r"# \S", lines[first]):
        title = title or lines[first][2:].strip()
        del lines[first]

    lines = _link_to_github(_convert_alerts(lines), source_dir)
    safe_title = title.replace('"', '\\"')
    return f'---\ntitle: "{safe_title}"\n---\n\n' + "\n".join(lines).strip() + "\n"


def _write_guide_pages(out):
    for page_path, (source, title) in GUIDE_PAGES.items():
        with open(os.path.join(REPO_ROOT, source)) as f:
            md = f.read()
        if not title and not re.match(r"# \S", md.lstrip()):
            title = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", posixpath.splitext(posixpath.basename(source))[0])
        mdx_path = os.path.join(out, page_path + ".mdx")
        os.makedirs(os.path.dirname(mdx_path), exist_ok=True)
        with open(mdx_path, "w") as f:
            f.write(_markdown_to_mdx(md, title, posixpath.dirname(source)))


def _reference_page_slug(out, resolved, anchor):
    for slug in (resolved, resolved + "/index"):
        if not os.path.exists(os.path.join(out, slug + ".fjson")):
            continue
        for source_path, classes in STORE_CLASS_SPLITS.items():
            if slug == source_path:
                cls = next((c for c in classes if c["class_id"] == anchor), classes[0])
                return cls["output_path"]
        return slug
    return None


def _absolute_reference_links(out):
    """Rewrite Sphinx's directory-relative page links to absolute page URLs."""

    def rewrite(body, base):
        def repl(match):
            href = match.group(1)
            if re.match(r"([a-z][a-z0-9+.-]*:|#|/)", href, re.IGNORECASE):
                return match.group(0)
            path, sep, anchor = href.partition("#")
            resolved = posixpath.normpath(posixpath.join(base, path))
            slug = _reference_page_slug(out, resolved, anchor)
            if slug is None:
                return match.group(0)
            return f'href="/{DOCS_V2_DIRECTORY}/{slug}{sep}{anchor}"'

        return re.sub(r'href="([^"]*)"', repl, body)

    for root, _, files in os.walk(os.path.join(out, "reference")):
        for name in files:
            if not name.endswith(".fjson"):
                continue
            fpath = os.path.join(root, name)
            page = os.path.relpath(fpath, out)[: -len(".fjson")].replace(os.sep, "/")
            base = page[: -len("index")] if page.endswith("index") else page + "/"
            with open(fpath) as f:
                data = json.load(f)
            data["body"] = rewrite(data["body"], base)
            with open(fpath, "w") as f:
                json.dump(data, f, indent=2)


def _postprocess_json_build(app, exception):
    if exception or app.builder.name != "json":
        return

    out = app.outdir

    _write_guide_pages(out)

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

    _absolute_reference_links(out)

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
