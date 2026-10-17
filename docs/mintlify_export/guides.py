"""Convert repository Markdown (README, CONTRIBUTING, guides) into MDX pages."""

import os
import posixpath
import re

# GitHub alert type to callout component.
ALERT_COMPONENTS = {
    "NOTE": "Note",
    "TIP": "Tip",
    "IMPORTANT": "Warning",
    "WARNING": "Warning",
    "CAUTION": "Warning",
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


def _link_to_github(lines, source_dir, blob_url):
    def repl(match):
        href = match.group(1)
        if re.match(r"([a-z][a-z0-9+.-]*:|#|/)", href, re.IGNORECASE):
            return match.group(0)
        path, sep, anchor = href.partition("#")
        target = posixpath.normpath(posixpath.join(source_dir, path))
        return f"]({blob_url}/{target}{sep}{anchor})"

    out, in_fence = [], False
    for line in lines:
        if _toggles_fence(line):
            in_fence = not in_fence
            out.append(line)
        else:
            out.append(line if in_fence else re.sub(r"\]\(([^)\s]+)\)", repl, line))
    return out


def markdown_to_mdx(md, title, source_dir, blob_url):
    """Return an MDX page for ``md``.

    ``source_dir`` is the Markdown file's directory relative to the repo root.
    Relative links are rewritten to ``blob_url``.
    """
    # The logo block uses <picture>/<source>, which MDX cannot parse.
    md = re.sub(
        r'<p align="center">\s*<picture>.*?</picture>\s*</p>\s*', "", md, flags=re.DOTALL
    )
    lines = md.split("\n")

    first = next((i for i, line in enumerate(lines) if line.strip()), None)
    if first is not None and re.match(r"# \S", lines[first]):
        title = title or lines[first][2:].strip()
        del lines[first]

    lines = _link_to_github(_convert_alerts(lines), source_dir, blob_url)
    safe_title = title.replace('"', '\\"')
    return f'---\ntitle: "{safe_title}"\n---\n\n' + "\n".join(lines).strip() + "\n"


def write_pages(out, root, pages, blob_url):
    """Write one MDX page per entry of ``pages`` under ``out``.

    ``pages`` maps an output page path to ``(markdown path relative to root,
    fixed title or "")``.
    """
    for page_path, (source, title) in pages.items():
        with open(os.path.join(root, source)) as f:
            md = f.read()
        if not title and not re.match(r"# \S", md.lstrip()):
            stem = posixpath.splitext(posixpath.basename(source))[0]
            title = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", stem)
        mdx_path = os.path.join(out, page_path + ".mdx")
        os.makedirs(os.path.dirname(mdx_path), exist_ok=True)
        with open(mdx_path, "w") as f:
            f.write(markdown_to_mdx(md, title, posixpath.dirname(source), blob_url))
