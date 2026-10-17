"""Build the API reference part of the navigation from the generated pages."""

PLACEHOLDER = "{reference}"
GROUP_ICON = "folder"


def page_parts(page):
    """Module path segments of a reference page, e.g. ``["auth_server", "mfa_client"]``."""
    parts = page.split("/")[1:]
    return parts[:-1] if parts and parts[-1] == "index" else parts


def reference_tree(site_dir, pages, first):
    """Group reference pages by top-level package.

    A package with several pages becomes a group, a package with one page is
    listed directly after the groups. Each part sorts by name, except that pages
    listed in ``first`` come first, in that order.
    """
    rank = {page: i for i, page in enumerate(first)}

    def order(page):
        return rank.get(page, len(rank))

    packages = {}
    for page in pages:
        packages.setdefault(page_parts(page)[0], []).append(page)

    items = []
    for package, members in packages.items():
        members.sort(key=lambda page: (order(page), page))
        urls = [f"{site_dir}/{page}" for page in members]
        if len(urls) == 1:
            node = urls[0]
        else:
            node = {
                "group": package.replace("_", " ").title(),
                "icon": GROUP_ICON,
                "expanded": True,
                "pages": urls,
            }
        items.append((isinstance(node, str), order(members[0]), package, node))
    return [item[-1] for item in sorted(items, key=lambda item: item[:3])]


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
