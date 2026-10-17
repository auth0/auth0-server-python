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
4. Splits configured module pages into per-class pages.
5. Writes each reference page as MDX and removes its `.fjson`. Module pages are titled by
   module path with a module icon, and single-class pages by class name with a class icon.
6. Writes `navigation.json` from `mintlify_navigation`, filling the `{reference}` placeholder
   with API reference groups built from the generated pages (one group per top-level package,
   a lone page is listed directly).

## Config values

| Name | Meaning |
|---|---|
| `mintlify_site_dir` | Page path prefix in the docs site |
| `mintlify_navigation` | Navigation tree written to `navigation.json`, with a `{reference}` placeholder |
| `mintlify_reference_first` | Optional. Reference page paths to list first |
| `mintlify_guides` | Output page to `(markdown path, fixed title or "")` |
| `mintlify_guides_root` | Absolute folder the guide paths are relative to |
| `mintlify_github_blob_url` | Base URL for relative Markdown links |
| `mintlify_remove_pages` | Reference page paths to drop |
| `mintlify_class_splits` | Module page to per-class page descriptors |

## Moving it out of this repo

Copy this folder next to the consuming `conf.py`, add its parent to `sys.path`,
list `"mintlify_export"` in `extensions`, and set the config values above.
