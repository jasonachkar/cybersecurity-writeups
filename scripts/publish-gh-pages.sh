#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SITE_INPUT="${1:-$REPOSITORY_ROOT/mkdocs-project/site}"
PUBLISH_CHECKOUT="${2:-}"

fail() {
  echo "gh-pages publication failed: $*" >&2
  exit 1
}

if [[ -z "$PUBLISH_CHECKOUT" ]]; then
  fail "usage: scripts/publish-gh-pages.sh <generated-site-directory> <clean-gh-pages-checkout>"
fi
if [[ ! -d "$SITE_INPUT" ]]; then
  fail "generated site directory does not exist: $SITE_INPUT"
fi
if [[ ! -d "$PUBLISH_CHECKOUT" ]]; then
  fail "gh-pages checkout does not exist: $PUBLISH_CHECKOUT"
fi

SITE_INPUT="$(cd "$SITE_INPUT" && pwd -P)"
PUBLISH_CHECKOUT="$(cd "$PUBLISH_CHECKOUT" && pwd -P)"

[[ "${GITHUB_EVENT_NAME:-}" == "push" ]] ||
  fail "publication is allowed only for a GitHub push event"
[[ "${GITHUB_REF:-}" == "refs/heads/main" ]] ||
  fail "publication is allowed only from refs/heads/main"
[[ "${SITE_SOURCE_BRANCH:-}" == "main" ]] ||
  fail "SITE_SOURCE_BRANCH must be main for public deployment"
[[ "${SITE_SOURCE_COMMIT:-}" =~ ^[0-9a-f]{40}$ ]] ||
  fail "SITE_SOURCE_COMMIT must be a full lowercase Git SHA"
[[ "${GITHUB_SHA:-}" == "$SITE_SOURCE_COMMIT" ]] ||
  fail "SITE_SOURCE_COMMIT must match the exact GitHub build commit"
[[ "${GITHUB_REPOSITORY:-}" == "jasonachkar/cybersecurity-writeups" ]] ||
  fail "unexpected GitHub repository: ${GITHUB_REPOSITORY:-unset}"

PUBLISH_TOP="$(git -C "$PUBLISH_CHECKOUT" rev-parse --show-toplevel 2>/dev/null)" ||
  fail "publication target is not a Git checkout"
PUBLISH_TOP="$(cd "$PUBLISH_TOP" && pwd -P)"
[[ "$PUBLISH_TOP" == "$PUBLISH_CHECKOUT" ]] ||
  fail "publication target must be the checkout root"
[[ "$(git -C "$PUBLISH_CHECKOUT" branch --show-current)" == "gh-pages" ]] ||
  fail "publication target is not on gh-pages"
[[ -z "$(git -C "$PUBLISH_CHECKOUT" status --porcelain)" ]] ||
  fail "gh-pages checkout must be clean before replacement"
[[ "$SITE_INPUT" != "$PUBLISH_CHECKOUT" ]] ||
  fail "generated site and publication checkout must be separate directories"

node "$REPOSITORY_ROOT/scripts/validate-generated-site.js" "$SITE_INPUT"

# Remove every previously tracked path before copying the clean build. A normal commit
# records deletions for pages that no longer exist; no force push is needed.
git -C "$PUBLISH_CHECKOUT" rm -r --ignore-unmatch -- .
cp -a "$SITE_INPUT"/. "$PUBLISH_CHECKOUT"/
node "$REPOSITORY_ROOT/scripts/validate-generated-site.js" "$PUBLISH_CHECKOUT"

git -C "$PUBLISH_CHECKOUT" add --all
[[ -z "$(git -C "$PUBLISH_CHECKOUT" ls-files --others --exclude-standard)" ]] ||
  fail "publication checkout contains untracked output after staging"

git -C "$PUBLISH_CHECKOUT" config user.name "github-actions[bot]"
git -C "$PUBLISH_CHECKOUT" config user.email "41898282+github-actions[bot]@users.noreply.github.com"

if git -C "$PUBLISH_CHECKOUT" diff --cached --quiet; then
  echo "Generated gh-pages tree is already current; no commit required."
else
  git -C "$PUBLISH_CHECKOUT" commit -m "Deploy $SITE_SOURCE_COMMIT"
  git -C "$PUBLISH_CHECKOUT" push origin HEAD:gh-pages
fi

LOCAL_TIP="$(git -C "$PUBLISH_CHECKOUT" rev-parse HEAD)"
REMOTE_TIP="$(git -C "$PUBLISH_CHECKOUT" ls-remote --exit-code origin refs/heads/gh-pages | awk '{print $1}')"
[[ "$LOCAL_TIP" == "$REMOTE_TIP" ]] ||
  fail "remote gh-pages tip $REMOTE_TIP does not match published commit $LOCAL_TIP"

echo "Published validated source $SITE_SOURCE_COMMIT to gh-pages with a normal push."
