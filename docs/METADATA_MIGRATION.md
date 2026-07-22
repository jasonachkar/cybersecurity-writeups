# Legacy metadata migration registry

New and substantively reviewed articles keep lifecycle metadata in YAML front matter.
Twenty legacy indexed pages predate that contract. Their conservative lifecycle fields
are recorded in `docs/content-metadata.json` so every indexed page has an explicit
review status without a bulk edit that might imply its content was reviewed.

Every registry entry is forced to `requires-review`, has no validation evidence, and
uses `sourceQuality: requires-review`. Month-level legacy publication dates are
preserved instead of inventing a day. When a reviewer checks a page:

1. verify material claims and examples against primary sources;
2. add the complete metadata contract to that page's front matter;
3. add or repair its References and validation sections;
4. remove its registry entry;
5. run `npm run metadata:check` and `npm run index:generate`.

The validator rejects stale registry paths and prevents a registry entry from claiming
verification. This is an honest adoption bridge, not evidence that legacy content is
current.
