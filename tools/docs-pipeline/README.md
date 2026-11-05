# Canonical documentation pipeline

`main` owns the Markdown, metadata, examples, MkDocs configuration, and build
inputs. `gh-pages` is a publication artifact and must not be edited as an
independent content source.

The Go command provides the deterministic boundary around MkDocs. Go is used
for path safety, source hashing, route contracts, artifact inventory, and
process orchestration. MkDocs remains responsible for Markdown rendering, and
DOM-specific presentation work should remain in a dedicated post-build step
until it can be moved into native MkDocs templates.

## Commands

Run unit tests:

```shell
cd tools/docs-pipeline
go test ./...
```

Build into the ignored staging directory using the exact Python dependencies
from `requirements-docs.txt`:

```shell
go run ./tools/docs-pipeline/main.go build \
  -python .venv/bin/python \
  -output .artifacts/site
```

Verify an existing staged build:

```shell
go run ./tools/docs-pipeline/main.go verify -site .artifacts/site
```

Print the canonical source hashes and source-to-route mapping:

```shell
go run ./tools/docs-pipeline/main.go inventory
```

Compare canonical routes with the lifecycle registry currently published on
`gh-pages`:

```shell
go run ./tools/docs-pipeline/main.go audit -published-ref origin/gh-pages
```

The ignored report at `.artifacts/live-content-gap.json` separates live
indexable routes with no canonical Markdown, canonical routes not classified by
the live registry, and historical Markdown retained behind archived URLs.
`-fail-on-gap` makes the first two classes blocking; archived source is allowed
only because the build verifies its `noindex` archive treatment.

The build command only accepts an output below `.artifacts/`, rejects symlinked
output paths, runs MkDocs in strict and clean mode, verifies that every
canonical Markdown route exists, and writes
`.artifacts/site/docs-build-manifest.json`. The manifest contains no timestamp,
so the same inputs and toolchain produce a directly comparable inventory.

`publishing/content-status.json` is the canonical URL lifecycle registry. Every
Markdown route has a registry entry, and its status/indexability are included in
the build manifest. `migrationMode` is `false`, so any future indexable lifecycle
entry without canonical Markdown fails the pipeline.

## Markdown inside HTML

Prefer ordinary Markdown for headings, links and lists. Raw block HTML suppresses
Markdown parsing. When a semantic container is needed, the configured `md_in_html`
extension requires `markdown="1"` on that container (and on each nested block
container that needs Markdown). The extension alone does not parse unmarked HTML.
See the [Python-Markdown documentation](https://python-markdown.github.io/extensions/md_in_html/).

`npm run docs:test:html` parses every built article with JavaScript disabled and
checks for unintended Markdown text, including non-indexable and archived routes.
The tested [failure fixture](../../tests/docs/fixtures/markdown-in-html.md) exercises
both ordinary Markdown and the explicit container opt-in using the installed
renderer and actual MkDocs extension configuration. Browser regressions in
`npm run docs:test:ui` check the repaired pages in both themes and screen sizes.

The DOM guard excludes code, preformatted text, scripts, styles, textareas, Mermaid
and source viewers. Intentional Markdown demonstrations in prose can use
`data-markdown-example="reason for this literal example"` on the smallest relevant
container. Numbered semantic headings, table-cell labels and prose dashes in real
list items are accepted. Do not exempt whole articles to silence a rendering bug.

## Migration rule

Do not automate HTML-to-Markdown scraping. Content that exists only on
`gh-pages` must be reviewed and migrated once into Markdown or classified as an
intentional archived route. The migration gate is now enforced by the canonical build. The current workflow
publishes from `main` only after content, secret and documentation checks pass;
it copies the exact verified artifact into `gh-pages` without rebuilding.
