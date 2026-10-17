# mintlify_export

Sphinx extension that post-processes the `json` builder output into docs-site
MDX pages and a `navigation.json`.

It uses only the standard library and imports nothing from the SDK or from
`conf.py`. Every project-specific value is a `mintlify_*` config value, so the
folder can be copied to another repo unchanged.

## What it does on `build-finished` (json builder only)

1. Converts Markdown guides (README, CONTRIBUTING, examples) to MDX. GitHub
   alerts become callouts. A relative link to another guide opens that guide's page and
   is followed by a GitHub link. Any other relative link points at `mintlify_github_blob_url`.
2. Removes unwanted reference pages.
3. Rewrites reference cross-links to absolute page URLs under `mintlify_site_dir`.
4. Writes each reference page as MDX and removes its `.fjson`. Pages are titled by
   module path, with a module icon. Code blocks get a copy button.
5. Writes `navigation.json` from `mintlify_navigation`, filling the `{reference}` placeholder
   with a tree that mirrors the package hierarchy: a package or subpackage becomes a group
   named after it, a module becomes a page. Groups sort before pages, each by name.

## Adding docs

Nothing to edit. New modules, packages and classes are picked up from the
generated pages, and new guides from the Markdown files in the guides folder.
Titles, sidebar labels, icons, colors and navigation groups are all derived.

## Config values

| Name | Meaning |
|---|---|
| `mintlify_site_dir` | Page path prefix in the docs site |
| `mintlify_navigation` | Navigation tree written to `navigation.json`, with a `{reference}` placeholder |
| `mintlify_guides` | Output page to `(markdown path, fixed title or "")` |
| `mintlify_guides_root` | Absolute folder the guide paths are relative to |
| `mintlify_github_blob_url` | Base URL for relative Markdown links |
| `mintlify_remove_pages` | Reference page paths to drop |

## Moving it out of this repo

Copy this folder next to the consuming `conf.py`, add its parent to `sys.path`,
list `"mintlify_export"` in `extensions`, and set the config values above.
