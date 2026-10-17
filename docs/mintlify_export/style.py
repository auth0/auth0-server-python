"""Colors for signatures and sidebar icons.

The docs site does not load Sphinx's theme CSS, so everything is styled here
and embedded in each generated page. One palette drives both: CSS variables
with a light default and a ``.dark`` override, since the docs site sets
``dark`` on the root element.
"""

import json

# One icon per kind of node. The page front matter, the navigation and the
# sidebar colors below all read these, so changing one keeps the rest in step.
GROUP_ICON = "folder"
MODULE_ICON = "file-code"
CLASS_ICON = "cube"

PALETTE = """:root{--sig-keyword:#7e22ce;--sig-name:#1d4ed8;--sig-type:#0f766e;--sig-default:#b45309;--sig-muted:#64748b}
.dark{--sig-keyword:#c084fc;--sig-name:#60a5fa;--sig-type:#5eead4;--sig-default:#fbbf24;--sig-muted:#94a3b8}
"""

SIGNATURES = """dt.sig{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.875rem;line-height:1.7;
padding:.5rem .75rem;border-radius:.5rem;background:rgba(127,127,127,.08);overflow-x:auto}
dt.sig em{font-style:normal}
dt.sig .pre{font-weight:400}
dt.sig .property,dt.sig .property .pre{color:var(--sig-keyword)}
dt.sig .sig-prename,dt.sig .sig-prename .pre{color:var(--sig-muted)}
dt.sig .sig-name,dt.sig .sig-name .pre{color:var(--sig-name);font-weight:600}
dt.sig .sig-param>.n:not(:first-child),dt.sig .sig-return-typehint{color:var(--sig-type)}
dt.sig .default_value{color:var(--sig-default)}
dt.sig .p,dt.sig .o,dt.sig .sig-paren,dt.sig .sig-return-icon{color:var(--sig-muted)}
dt.sig .sig-import{display:block;font-weight:400;margin-bottom:.4rem;padding-bottom:.4rem;font-size:.8125rem;
border-bottom:1px solid rgba(127,127,127,.25);color:var(--sig-muted);overflow-wrap:anywhere}
dt.sig .sig-import .kw{color:var(--sig-keyword)}
dt.sig .sig-import .nm{color:var(--sig-name);font-weight:600}
"""


def _sidebar_icons(site_dir):
    """Color sidebar icons by kind: package (amber), module (blue), class (purple).

    The docs site draws each icon as an element masked by its icon file, so the
    kind is matched on the icon name and scoped to this SDK's pages.
    """
    prefix = f"/{site_dir}/"
    return (
        f'li:has(a[href^="{prefix}"])>button svg[style*="/{GROUP_ICON}.svg"]{{background-color:var(--sig-default)}}\n'
        f'a[href^="{prefix}"] svg[style*="/{MODULE_ICON}.svg"]{{background-color:var(--sig-name)}}\n'
        f'a[href^="{prefix}"] svg[style*="/{CLASS_ICON}.svg"]{{background-color:var(--sig-keyword)}}\n'
    )


def guide_css(site_dir):
    return PALETTE + _sidebar_icons(site_dir)


def reference_css(site_dir):
    return PALETTE + _sidebar_icons(site_dir) + SIGNATURES


def as_html_tag(css):
    return f"<style>\n{css}</style>\n"


def as_mdx_element(css):
    # A <style> element written directly in MDX is dropped by the docs site.
    return f"<div dangerouslySetInnerHTML={{{{__html: {json.dumps(as_html_tag(css))}}}}} />"
