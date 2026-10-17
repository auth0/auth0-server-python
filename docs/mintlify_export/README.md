# mintlify_export

Sphinx extension that post-processes the `json` builder output into docs-site
MDX pages and a `navigation.json`.

It uses only the standard library and imports nothing from the SDK or from
`conf.py`. Every project-specific value is a `mintlify_*` config value, so the
folder can be copied to another repo unchanged.

## What it does on `build-finished` (json builder only)

1. Converts Markdown guides (README, CONTRIBUTING, examples) to MDX. GitHub
   alerts become callouts and relative links point at `mintlify_github_blob_url`.
2. Applies title overrides and removes unwanted reference pages.
3. Rewrites reference cross-links to absolute page URLs under `mintlify_site_dir`.
4. Splits configured module pages into per-class pages.
5. Writes each reference page as MDX and removes its `.fjson`.
6. Writes `navigation.json` from `mintlify_navigation`.

## Config values

| Name | Meaning |
|---|---|
| `mintlify_site_dir` | Page path prefix in the docs site |
| `mintlify_navigation` | Navigation tree written to `navigation.json` |
| `mintlify_guides` | Output page to `(markdown path, fixed title or "")` |
| `mintlify_guides_root` | Absolute folder the guide paths are relative to |
| `mintlify_github_blob_url` | Base URL for relative Markdown links |
| `mintlify_title_overrides` | Reference page path to title |
| `mintlify_remove_pages` | Reference page paths to drop |
| `mintlify_class_splits` | Module page to per-class page descriptors |

## Moving it out of this repo

Copy this folder next to the consuming `conf.py`, add its parent to `sys.path`,
list `"mintlify_export"` in `extensions`, and set the config values above.
