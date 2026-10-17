"""Post-process Sphinx JSON reference pages into MDX pages."""

import json
import os
import posixpath
import re

from .navigation import page_parts
from .style import MODULE_ICON, as_html_tag, reference_css


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


def _page_slug(out, resolved):
    for slug in (resolved, resolved + "/index"):
        if os.path.exists(os.path.join(out, slug + ".fjson")):
            return slug
    return None


def absolutize_links(out, site_dir):
    """Rewrite Sphinx's directory-relative page links to absolute page URLs."""

    def rewrite(body, base):
        def repl(match):
            href = match.group(1)
            if re.match(r"([a-z][a-z0-9+.-]*:|#|/)", href, re.IGNORECASE):
                return match.group(0)
            path, sep, anchor = href.partition("#")
            resolved = posixpath.normpath(posixpath.join(base, path))
            slug = _page_slug(out, resolved)
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


# Inline handler, because scripts inside injected HTML do not run.
_COPY_BUTTON = (
    '<button type="button" class="copy-btn" aria-label="Copy code" title="Copy" '
    'onclick="var b=this;navigator.clipboard.writeText(b.parentElement.querySelector(\'pre\').innerText);'
    "b.dataset.copied='1';setTimeout(function(){delete b.dataset.copied},1500)\">"
    '<svg class="i-copy" viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" '
    'stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="5.5" y="5.5" width="8" '
    'height="8" rx="1.5"/><path d="M10.5 3.5v-1a1 1 0 0 0-1-1h-6a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h1"/></svg>'
    '<svg class="i-check" viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" '
    'stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M3 8.5l3.2 3.2L13 5"/></svg>'
    "</button>"
)


def _add_copy_buttons(html):
    """Add a copy button to every highlighted code block."""
    return re.sub(
        r'(<div class="highlight-[\w+-]+ notranslate">)',
        lambda match: match.group(1) + _COPY_BUTTON,
        html,
    )


def _html_to_mdx(frontmatter, html, css):
    html = re.sub(r'<a class="headerlink"[^>]*>.*?</a>', "", html)
    # Drop the first <h1>, the docs site renders the title itself.
    html = re.sub(r"<h1[^>]*>.*?</h1>", "", html, count=1, flags=re.DOTALL)
    header = "".join(
        f'{key}: "{value.replace(chr(34), chr(92) + chr(34))}"\n'
        for key, value in frontmatter.items()
    )
    body = as_html_tag(css) + _add_copy_buttons(html.strip())
    return (
        f"---\n{header}---\n\n"
        f"export const rawHtml = {json.dumps(body)};\n\n"
        "<div dangerouslySetInnerHTML={{__html: rawHtml}} />\n"
    )


def _frontmatter(page):
    parts = page_parts(page)
    return {"title": ".".join(parts), "sidebarTitle": parts[-1], "icon": MODULE_ICON}


def write_mdx(out, site_dir):
    """Write an MDX page beside each reference page, then remove the JSON.

    Pages are titled by module path, with a module icon and the last path
    segment as the sidebar label. Returns the written page paths, without
    extension.
    """
    css = reference_css(site_dir)
    pages = []
    for fpath in list(_page_files(out)):
        data = _load(fpath)
        if not data.get("body"):
            continue
        page = os.path.relpath(fpath, out)[: -len(".fjson")].replace(os.sep, "/")
        with open(fpath[: -len(".fjson")] + ".mdx", "w") as f:
            f.write(_html_to_mdx(_frontmatter(page), data["body"], css))
        os.remove(fpath)
        pages.append(page)
    return sorted(pages)
