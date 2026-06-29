#!/usr/bin/env bash
set -eu
set -o pipefail

# Deploys the MkDocs documentation site.
# It activates the virtual environment, validates files, and runs the build.
#
# Usage:
#   ./scripts/deploy-docs.sh [--deploy]

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "==> Activating Python Virtual Environment..."
if [ ! -d ".venv" ]; then
  echo "Error: Virtual environment (.venv) not found. Run python3 -m venv .venv and install dependencies first."
  exit 1
fi

source .venv/bin/activate

echo "==> Verifying site build..."
# Build with strict settings to identify dead links or config errors
mkdocs build -f mkdocs-project/mkdocs.yml --strict

echo "==> Build completed successfully! Output is in 'mkdocs-project/site/' directory."

# If --deploy flag is provided, trigger the GitHub pages deploy
if [[ "${1:-}" == "--deploy" ]]; then
  echo "==> Deploying documentation site to GitHub Pages..."
  mkdocs gh-deploy -f mkdocs-project/mkdocs.yml --force
  echo "==> Deployment completed successfully! Docs are live."
fi
