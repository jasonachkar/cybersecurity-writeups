#!/usr/bin/env bash
# Run the MCP tool-authorization lab: pin check, 33 mechanism tests, then the scenario matrix.
#   bash labs/mcp-tool-authorization/scripts/run-lab.sh [--publish-evidence]
# Needs only Node.js 22+. No network, no model, no credentials, no Docker. The tool server is a local
# child process whose every effect is an in-memory array append.
set -euo pipefail

lab_root="$(cd "$(dirname "$0")/.." && pwd)"
repo_root="$(cd "$lab_root/../.." && pwd)"
out="${LAB_OUT:-$repo_root/.artifacts/research/mcp-tool-authorization}"
publish=0
[ "${1:-}" = "--publish-evidence" ] && publish=1
rm -rf "$out"
mkdir -p "$out"

{
  echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "node=$(node --version)"
  echo "kernel=$(uname -r)"
  echo "policy_version=$(node -e 'console.log(require(process.argv[1]).version)' "$lab_root/policy.json")"
  echo "mcp_spec_revision_read=2025-11-25 (message shapes only; the mock server is not a conformant MCP server)"
} | tee "$out/versions.txt"

echo "== descriptor pins"
node "$lab_root/scripts/pin.js" | tee "$out/pins.txt"

echo "== mechanism tests"
node --test "$lab_root/tests/gateway.test.js" >"$out/unit-tests.txt" 2>&1 || { tail -40 "$out/unit-tests.txt"; exit 1; }
grep -E "^# (tests|pass|fail)" "$out/unit-tests.txt"

echo "== scenario matrix (expectations declared before each step)"
node "$lab_root/scripts/run-scenarios.js" "$out" | tee "$out/scenarios.txt"

if [ "$publish" = 1 ]; then
  ev="$lab_root/evidence"
  mkdir -p "$ev"
  find "$ev" -maxdepth 1 -type f -delete
  cp "$out/versions.txt" "$out/pins.txt" "$out/scenarios.txt" "$out/decision-matrix.json" "$out/decision-matrix-table.txt" "$ev/"
  grep -E "^# (tests|pass|fail)" "$out/unit-tests.txt" >"$ev/unit-test-summary.txt"
  echo "evidence copied to ${ev#"$repo_root"/}"
fi
