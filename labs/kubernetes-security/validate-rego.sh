#!/usr/bin/env bash
# Native OPA check of policies/rego/workload.rego: unit tests, then the policy evaluated over
# the baseline manifests, the hardened manifests and the admission case corpus.
# Uses a local `opa` if present, otherwise the OPA 1.17.0 image pinned by digest (same pin as labs/iac-policy).
# Needs: node (npm ci first, for the YAML parser) and python3. No cluster, no network at evaluation time.
set -euo pipefail
lab_root="$(cd "$(dirname "$0")" && pwd)"
image=openpolicyagent/opa:1.17.0@sha256:3c6e9e4d433b6e94df424c3385134312a95042aa991cdfc8e01944115675fb9d
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
# The OPA image runs as a non-root user; mktemp creates the directory private to us.
chmod 0755 "$work"

if command -v opa >/dev/null 2>&1; then
  opa_run() { opa "$@"; }
  policy_dir="$lab_root/policies/rego"; input_dir="$work"
else
  command -v docker >/dev/null 2>&1 || { echo 'Install OPA or Docker.' >&2; exit 1; }
  docker pull -q "$image" >/dev/null
  opa_run() { docker run --rm --network none -v "$lab_root:/lab:ro" -v "$work:/work:ro" -w /lab "$image" "$@"; }
  policy_dir=/lab/policies/rego; input_dir=/work
fi

opa_run test "$policy_dir"

node "$lab_root/scripts/manifests-to-input.js" "$lab_root/baseline" >"$work/baseline.json"
node "$lab_root/scripts/manifests-to-input.js" "$lab_root/hardened" >"$work/hardened.json"
node "$lab_root/scripts/manifests-to-input.js" "$lab_root/admission-cases/cases.yaml" >"$work/cases.json"
chmod 0644 "$work"/*.json
opa_run eval -d "$policy_dir" -i "$input_dir/baseline.json" 'data.lab.k8s.workload.deny' --format json >"$work/baseline-result.json"
opa_run eval -d "$policy_dir" -i "$input_dir/hardened.json" 'data.lab.k8s.workload.deny' --format json >"$work/hardened-result.json"
opa_run eval -d "$policy_dir" -i "$input_dir/cases.json" 'data.lab.k8s.workload.pod_violations' --format json >"$work/cases-result.json"

python3 - "$work" "$lab_root" <<'PY'
import collections, json, pathlib, sys

work, lab = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
value = lambda name: json.loads((work / name).read_text())["result"][0]["expressions"][0]["value"]

baseline = value("baseline-result.json")
rules = {v["rule"] for v in baseline}
required = {"privileged", "hostpath", "host-namespace", "run-as-root", "psa-enforce", "default-deny-network",
            "rbac-secrets-read", "rbac-exec", "rbac-binding-creation", "service-account-token", "resource-limits", "seccomp"}
assert required <= rules, f"baseline is missing expected violations: {sorted(required - rules)}"
hardened = value("hardened-result.json")
assert hardened == [], f"hardened manifests must have no violations: {hardened}"

expect = json.loads((lab / "admission-cases" / "expectations.json").read_text())["cases"]
denied = collections.defaultdict(set)
for v in value("cases-result.json"):
    denied[v["object"].split("/", 1)[1]].add(v["rule"])
mismatch = {c: (e["opa"], "deny" if denied.get(c) else "allow") for c, e in expect.items() if e["opa"] != ("deny" if denied.get(c) else "allow")}
assert not mismatch, f"OPA decisions differ from expectations.json: {mismatch}"
print(f"PASS: baseline {len(baseline)} violations across {len(rules)} rules; hardened 0; {len(expect)} admission cases match their predicted OPA decision.")
PY
