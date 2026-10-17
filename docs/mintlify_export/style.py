"""Colors for signatures, code blocks and sidebar icons.

The docs site does not load Sphinx's theme CSS, so everything is styled here
and embedded in each generated page. One palette drives all of it: CSS
variables with a light default and a ``.dark`` override, since the docs site
sets ``dark`` on the root element.
"""

import json

# One icon per kind of node. The page front matter, the navigation and the
# sidebar colors below all read these, so changing one keeps the rest in step.
GROUP_ICON = "folder"
MODULE_ICON = "file-code"

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
dt.sig{position:relative;padding-right:4.5rem}
dt.sig a:has(.viewcode-link){position:absolute;top:.5rem;right:.75rem;font-size:.75rem;color:var(--sig-muted);text-decoration:none}
dt.sig .viewcode-link{font-weight:400}
div[class^=highlight-]{position:relative;margin:.5rem 0}
div.highlight{margin:0;padding:.5rem .75rem;border-radius:.5rem;background:rgba(127,127,127,.08);overflow-x:auto}
div.highlight pre{display:block;margin:0;padding:0;border:0;background:transparent;color:inherit;
font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.8125rem;line-height:1.7;
white-space:pre-wrap;overflow-wrap:anywhere;padding-right:2.25rem}
p.rubric{margin:1rem 0 .25rem;font-size:.75rem;font-weight:600;letter-spacing:.04em;text-transform:uppercase;color:var(--sig-muted)}
.copy-btn{position:absolute;top:.3125rem;right:.375rem;z-index:1;display:flex;align-items:center;justify-content:center;
width:1.75rem;height:1.75rem;border:0;border-radius:.375rem;background:transparent;color:var(--sig-muted);
cursor:pointer;opacity:.6}
.copy-btn:hover{opacity:1;background:rgba(127,127,127,.18)}
.copy-btn .i-check{display:none;color:var(--sig-type)}
.copy-btn[data-copied] .i-copy{display:none}
.copy-btn[data-copied] .i-check{display:block}
.highlight .k,.highlight .kn,.highlight .kd,.highlight .kc,.highlight .kp,.highlight .kr,.highlight .ow,.highlight .nd{color:var(--sig-keyword)}
.highlight .nn,.highlight .o,.highlight .p,.highlight .c,.highlight .c1,.highlight .cm,.highlight .cs{color:var(--sig-muted)}
.highlight .nf,.highlight .nc,.highlight .fm{color:var(--sig-name);font-weight:600}
.highlight .nb,.highlight .bp,.highlight .kt,.highlight .m,.highlight .mi,.highlight .mf,.highlight .mh{color:var(--sig-type)}
.highlight .s,.highlight .s1,.highlight .s2,.highlight .sa,.highlight .sb,.highlight .sc,.highlight .sd,.highlight .se,.highlight .si,.highlight .sx,.highlight .sr,.highlight .ss{color:var(--sig-default)}
.highlight .c,.highlight .c1,.highlight .cm,.highlight .cs{font-style:italic}
"""


def _sidebar_icons(site_dir):
    """Color sidebar icons by kind: package (amber), module (blue).

    The docs site draws each icon as an element masked by its icon file, so the
    kind is matched on the icon name and scoped to this SDK's pages.
    """
    prefix = f"/{site_dir}/"
    return (
        f'li:has(a[href^="{prefix}"])>button svg[style*="/{GROUP_ICON}.svg"]{{background-color:var(--sig-default)}}\n'
        f'a[href^="{prefix}"] svg[style*="/{MODULE_ICON}.svg"]{{background-color:var(--sig-name)}}\n'
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
