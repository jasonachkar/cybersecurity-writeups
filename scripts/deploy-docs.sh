#!/usr/bin/env bash
set -eu
set -o pipefail

# Local compatibility wrapper. Publication is performed only by the gated
# GitHub Actions workflow from its already-verified artifact.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [[ "${1:-}" == "--deploy" ]]; then
  echo "Direct deployment is disabled. Push a reviewed commit to main; CI publishes the exact verified artifact." >&2
  exit 2
fi
npm run verify:docs
