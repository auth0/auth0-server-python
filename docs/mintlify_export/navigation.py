"""Build the API reference part of the navigation from the generated pages."""

from .style import GROUP_ICON

PLACEHOLDER = "{reference}"


def page_parts(page):
    """Module path segments of a reference page, e.g. ``["auth_server", "mfa_client"]``."""
    parts = page.split("/")[1:]
    return parts[:-1] if parts and parts[-1] == "index" else parts


def _items(site_dir, children):
    groups, leaves = [], []
    for name in sorted(children):
        entry = children[name]
        if not entry["children"]:
            leaves.append(f"{site_dir}/{entry['page']}")
            continue
        group = {
            "group": name,
            "icon": GROUP_ICON,
            "expanded": True,
            "pages": _items(site_dir, entry["children"]),
        }
        if entry["page"]:
            group["root"] = f"{site_dir}/{entry['page']}"
        groups.append(group)
    return groups + leaves


def reference_tree(site_dir, pages):
    """Mirror the package hierarchy of the reference pages.

    A package or subpackage with pages below it becomes a group named after it,
    and a module becomes a page. Groups sort before pages, each by name, as in
    a file browser.
    """
    root = {}
    for page in pages:
        children = root
        for name in page_parts(page)[:-1]:
            children = children.setdefault(name, {"page": None, "children": {}})["children"]
        leaf = children.setdefault(page_parts(page)[-1], {"page": None, "children": {}})
        leaf["page"] = page
    return _items(site_dir, root)


def fill(nodes, items):
    """Replace ``PLACEHOLDER`` in a navigation tree with ``items``."""
    out = []
    for node in nodes:
        if node == PLACEHOLDER:
            out.extend(items)
        elif isinstance(node, dict):
            out.append({**node, "pages": fill(node["pages"], items)})
        else:
            out.append(node)
    return out
