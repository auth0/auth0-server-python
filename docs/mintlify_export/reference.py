"""Post-process Sphinx JSON reference pages into MDX pages."""

import json
import os
import posixpath
import re

from .navigation import page_parts
from .style import CLASS_ICON, MODULE_ICON, as_html_tag, reference_css


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


def _html_to_mdx(frontmatter, html, css):
    html = re.sub(r'<a class="headerlink"[^>]*>.*?</a>', "", html)
    # Drop the first <h1>, the docs site renders the title itself.
    html = re.sub(r"<h1[^>]*>.*?</h1>", "", html, count=1, flags=re.DOTALL)
    header = "".join(
        f'{key}: "{value.replace(chr(34), chr(92) + chr(34))}"\n'
        for key, value in frontmatter.items()
    )
    return (
        f"---\n{header}---\n\n"
        f"export const rawHtml = {json.dumps(as_html_tag(css) + html.strip())};\n\n"
        "<div dangerouslySetInnerHTML={{__html: rawHtml}} />\n"
    )


_TOP_LEVEL_SIGNATURE = re.compile(
    r'(<dl class="py (?:class|function|exception)">\s*'
    r'<dt class="sig sig-object py" id="([^"]+)">)'
)


def _add_import_lines(html, module, root):
    """Put ``from <root>.<module> import <Name>`` at the top of each top-level signature."""

    def repl(match):
        parent, _, name = match.group(2).rpartition(".")
        if parent != module:
            return match.group(0)
        line = (
            '<span class="sig-import"><span class="kw">from</span> '
            f'<span class="mod">{root}.{module}</span> '
            f'<span class="kw">import</span> <span class="nm">{name}</span></span>'
        )
        return match.group(1) + line

    return _TOP_LEVEL_SIGNATURE.sub(repl, html)


def _frontmatter(page, data, class_pages):
    if page in class_pages:
        name = data.get("title", "")
        return {"title": name, "sidebarTitle": name, "icon": CLASS_ICON}
    parts = page_parts(page)
    return {"title": ".".join(parts), "sidebarTitle": parts[-1], "icon": MODULE_ICON}


def write_mdx(out, class_pages, site_dir, import_root):
    """Write an MDX page beside each reference page, then remove the JSON.

    Module pages are titled by module path with a module icon. ``class_pages``
    are page paths that hold a single class, titled by class with a class icon.
    Returns the written page paths, without extension.
    """
    css = reference_css(site_dir)
    pages = []
    for fpath in list(_page_files(out)):
        data = _load(fpath)
        if not data.get("body"):
            continue
        page = os.path.relpath(fpath, out)[: -len(".fjson")].replace(os.sep, "/")
        parts = page_parts(page)
        module = ".".join(parts[:-1] if page in class_pages else parts)
        body = _add_import_lines(data["body"], module, import_root) if import_root else data["body"]
        with open(fpath[: -len(".fjson")] + ".mdx", "w") as f:
            f.write(_html_to_mdx(_frontmatter(page, data, class_pages), body, css))
        os.remove(fpath)
        pages.append(page)
    return sorted(pages)
