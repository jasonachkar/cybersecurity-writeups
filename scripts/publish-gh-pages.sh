#!/usr/bin/env bash
set -euo pipefail

site="${1:?verified site directory is required}"
target="${2:?gh-pages checkout directory is required}"

site="$(cd "$site" && pwd -P)"
target="$(cd "$target" && pwd -P)"

if [[ ! -f "$site/index.html" || ! -f "$site/CNAME" || ! -f "$site/.nojekyll" || ! -f "$site/docs-build-manifest.json" ]]; then
  echo "Refusing publication: verified site is incomplete." >&2
  exit 1
fi
if [[ ! -d "$target/.git" ]]; then
  echo "Refusing publication: target is not an isolated git checkout." >&2
  exit 1
fi
if [[ "$(basename "$target")" != "published-site" ]]; then
  echo "Refusing publication: unexpected target directory $target." >&2
  exit 1
fi

rsync --archive --delete --exclude='.git/' "$site/" "$target/"
git -C "$target" add --all
if git -C "$target" diff --cached --quiet; then
  echo "The verified site already matches gh-pages."
  exit 0
fi
git -C "$target" config user.name "github-actions[bot]"
git -C "$target" config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git -C "$target" commit -m "Deploy ${SITE_SOURCE_COMMIT:?source commit is required}"
git -C "$target" push origin HEAD:gh-pages
