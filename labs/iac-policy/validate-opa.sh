#!/usr/bin/env bash
set -euo pipefail
lab_root="$(cd "$(dirname "$0")" && pwd)"
if command -v opa >/dev/null 2>&1; then
  runner=(opa)
else
  command -v docker >/dev/null 2>&1 || { echo 'Install OPA 1.17.0 or Docker.' >&2; exit 1; }
  docker pull openpolicyagent/opa:1.17.0@sha256:3c6e9e4d433b6e94df424c3385134312a95042aa991cdfc8e01944115675fb9d
  runner=(docker run --rm --network none -v "$lab_root:/lab:ro" -w /lab openpolicyagent/opa:1.17.0@sha256:3c6e9e4d433b6e94df424c3385134312a95042aa991cdfc8e01944115675fb9d)
fi
cd "$lab_root"
for fixture in secure insecure unknown deleted; do
  input="fixtures/${fixture}_plan.json"
  if [[ "$fixture" == deleted ]]; then input=fixtures/deleted_control_plan.json; fi
  "${runner[@]}" test policy/terraform.rego "policy/${fixture}_fixture_test.rego" "$input" -v
done
