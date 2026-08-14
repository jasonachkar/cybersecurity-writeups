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

## Migration rule

Do not automate HTML-to-Markdown scraping. Content that exists only on
`gh-pages` must be reviewed and migrated once into Markdown or classified as an
intentional archived route. Deployment from `main` remains disabled until that
gap inventory is empty and the current post-processing behavior is reproducible
from files committed on `main`.
