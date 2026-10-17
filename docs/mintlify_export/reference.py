"""Post-process Sphinx JSON reference pages into MDX pages."""

import json
import os
import posixpath
import re


def _load(path):
    with open(path) as f:
        return json.load(f)


def _dump(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def _page_files(out):
    for root, _, files in os.walk(os.path.join(out, "reference")):
        for name in files:
            if name.endswith(".fjson"):
                yield os.path.join(root, name)


def apply_title_overrides(out, overrides):
    for page_path, title in overrides.items():
        fpath = os.path.join(out, page_path + ".fjson")
        if not os.path.exists(fpath):
            continue
        data = _load(fpath)
        data["title"] = title
        _dump(fpath, data)


def remove_pages(out, pages):
    for page_path in pages:
        fpath = os.path.join(out, page_path + ".fjson")
        if os.path.exists(fpath):
            os.remove(fpath)


def _page_slug(out, resolved, anchor, splits):
    for slug in (resolved, resolved + "/index"):
        if not os.path.exists(os.path.join(out, slug + ".fjson")):
            continue
        for source_path, classes in splits.items():
            if slug == source_path:
                cls = next((c for c in classes if c["class_id"] == anchor), classes[0])
                return cls["output_path"]
        return slug
    return None


def absolutize_links(out, site_dir, splits):
    """Rewrite Sphinx's directory-relative page links to absolute page URLs."""

    def rewrite(body, base):
        def repl(match):
            href = match.group(1)
            if re.match(r"([a-z][a-z0-9+.-]*:|#|/)", href, re.IGNORECASE):
                return match.group(0)
            path, sep, anchor = href.partition("#")
            resolved = posixpath.normpath(posixpath.join(base, path))
            slug = _page_slug(out, resolved, anchor, splits)
            if slug is None:
                return match.group(0)
            return f'href="/{site_dir}/{slug}{sep}{anchor}"'

        return re.sub(r'href="([^"]*)"', repl, body)

    for fpath in _page_files(out):
        page = os.path.relpath(fpath, out)[: -len(".fjson")].replace(os.sep, "/")
        base = page[: -len("index")] if page.endswith("index") else page + "/"
        data = _load(fpath)
        data["body"] = rewrite(data["body"], base)
        _dump(fpath, data)


def _split_class_blocks(body):
    """Return a list of HTML strings, one per <dl class="py class"> block."""
    starts = [m.start() for m in re.finditer(r'<dl class="py class">', body)]
    if not starts:
        return []
    return [
        body[start : (starts[i + 1] if i + 1 < len(starts) else len(body))]
        for i, start in enumerate(starts)
    ]


def split_pages(out, splits):
    """Split a single module page into per-class pages.

    ``splits`` maps a source page path (no extension) to a list of class
    descriptors with ``class_id``, ``title`` and ``output_path``.
    """
    for source_path, classes in splits.items():
        source_fpath = os.path.join(out, source_path + ".fjson")
        if not os.path.exists(source_fpath):
            continue
        source_data = _load(source_fpath)
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
            _dump(out_fpath, page_data)
        os.remove(source_fpath)


def _html_to_mdx(title, html):
    html = re.sub(r'<a class="headerlink"[^>]*>.*?</a>', "", html)
    # Drop the first <h1>, the docs site renders the title itself.
    html = re.sub(r"<h1[^>]*>.*?</h1>", "", html, count=1, flags=re.DOTALL)
    safe_title = title.replace('"', '\\"')
    return (
        f'---\ntitle: "{safe_title}"\n---\n\n'
        f"export const rawHtml = {json.dumps(html.strip())};\n\n"
        "<div dangerouslySetInnerHTML={{__html: rawHtml}} />\n"
    )


def write_mdx(out):
    """Write an MDX page beside each reference page, then remove the JSON."""
    for fpath in list(_page_files(out)):
        data = _load(fpath)
        if not data.get("body"):
            continue
        with open(fpath[: -len(".fjson")] + ".mdx", "w") as f:
            f.write(_html_to_mdx(data.get("title", ""), data["body"]))
        os.remove(fpath)
