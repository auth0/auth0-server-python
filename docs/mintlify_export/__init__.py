"""Sphinx extension that turns the ``json`` build into docs-site MDX pages.

Self-contained: standard library only, no imports from the SDK or from conf.py.
All project-specific values come from the ``mintlify_*`` config values below,
so the folder can be moved to another repo as is.
"""

import json
import os

from . import guides, reference

__all__ = ["setup"]


def _on_build_finished(app, exception):
    if exception or app.builder.name != "json":
        return

    cfg = app.config
    out = app.outdir

    guides.write_pages(
        out, cfg.mintlify_guides_root, cfg.mintlify_guides, cfg.mintlify_github_blob_url
    )
    reference.apply_title_overrides(out, cfg.mintlify_title_overrides)
    reference.remove_pages(out, cfg.mintlify_remove_pages)
    reference.absolutize_links(out, cfg.mintlify_site_dir, cfg.mintlify_class_splits)
    reference.split_pages(out, cfg.mintlify_class_splits)
    reference.write_mdx(out)

    nav_path = os.path.join(out, "navigation.json")
    with open(nav_path, "w") as f:
        json.dump({"pages": cfg.mintlify_navigation}, f, indent=2)

    print(f"[mintlify_export] Wrote {nav_path}")


def setup(app):
    # Directory prefix of every page in the docs site, e.g. "docs/sdk/python/server".
    app.add_config_value("mintlify_site_dir", "", "")
    # Navigation tree written to navigation.json.
    app.add_config_value("mintlify_navigation", [], "")
    # Output page path -> (Markdown path relative to mintlify_guides_root, fixed title or "").
    app.add_config_value("mintlify_guides", {}, "")
    # Absolute path of the folder holding the guide Markdown files.
    app.add_config_value("mintlify_guides_root", "", "")
    # Base URL that relative Markdown links are rewritten to.
    app.add_config_value("mintlify_github_blob_url", "", "")
    # Reference page path (no extension) -> title.
    app.add_config_value("mintlify_title_overrides", {}, "")
    # Reference page paths (no extension) to drop.
    app.add_config_value("mintlify_remove_pages", [], "")
    # Module page path -> list of {class_id, title, output_path} per-class pages.
    app.add_config_value("mintlify_class_splits", {}, "")
    app.connect("build-finished", _on_build_finished)
    return {"parallel_read_safe": True, "parallel_write_safe": True}
