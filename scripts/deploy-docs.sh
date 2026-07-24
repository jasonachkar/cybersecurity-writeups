#!/usr/bin/env bash
set -euo pipefail

# Build and validate the site locally. Publication is intentionally performed only
# by the main-branch GitHub Actions deployment job, which uses a scoped token and a
# normal (non-force) push to gh-pages.

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPOSITORY_ROOT"

if [[ "$#" -ne 0 ]]; then
  echo "Usage: ./scripts/deploy-docs.sh" >&2
  echo "This command builds and validates only; public deployment runs from validated main." >&2
  exit 2
fi

if [[ -x ".venv/bin/python" ]]; then
  PYTHON=".venv/bin/python"
elif [[ -x ".venv/Scripts/python.exe" ]]; then
  PYTHON=".venv/Scripts/python.exe"
else
  echo "Error: .venv does not contain a usable Python interpreter." >&2
  echo "Create the environment and install requirements-docs.txt first." >&2
  exit 1
fi

command -v node >/dev/null 2>&1 || {
  echo "Error: Node.js is required for deterministic staging and site validation." >&2
  exit 1
}

export SITE_SOURCE_BRANCH="${SITE_SOURCE_BRANCH:-$(git branch --show-current)}"
export SITE_SOURCE_COMMIT="${SITE_SOURCE_COMMIT:-$(git rev-parse HEAD)}"
export SITE_BUILD_TIMESTAMP="${SITE_BUILD_TIMESTAMP:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}"

echo "==> Preparing cross-platform documentation staging"
node scripts/prepare-mkdocs.js

echo "==> Building documentation in strict clean mode"
mkdir -p mkdocs-project/site
printf 'This file must be removed by mkdocs --clean.\n' > mkdocs-project/site/stale-output-sentinel.html
"$PYTHON" -m mkdocs build -f mkdocs-project/mkdocs.yml --strict --clean
: > mkdocs-project/site/.nojekyll

echo "==> Validating generated provenance, canonical URLs, sitemap, and clean output"
node scripts/validate-generated-site.js mkdocs-project/site

echo "==> Validated site is available in mkdocs-project/site/"
