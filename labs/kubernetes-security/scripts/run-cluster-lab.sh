#!/usr/bin/env bash
# Run the Kubernetes lab on a LOCAL, DISPOSABLE kind cluster, end to end.
#
#   bash labs/kubernetes-security/scripts/run-cluster-lab.sh [--use-existing] [--keep-cluster] [--publish-evidence]
#
# Needs: docker, kind, kubectl, node (npm ci first), python3, and the images
# dockerlab/posture:{insecure,hardened} (built by labs/docker-security). Optional,
# recorded as "not executed" when missing: kyverno, opa, kubeconform.
# Raw output: $LAB_OUT (default .artifacts/research/kubernetes-security, git-ignored).
# Creates a kind cluster named $LAB_CLUSTER (default k8s-sec-lab) and deletes it on
# exit unless --keep-cluster. Touches no other cluster or kubeconfig context.
set -euo pipefail

lab_root="$(cd "$(dirname "$0")/.." && pwd)"
repo_root="$(cd "$lab_root/../.." && pwd)"
out="${LAB_OUT:-$repo_root/.artifacts/research/kubernetes-security}"
cluster="${LAB_CLUSTER:-k8s-sec-lab}"
ctx="kind-$cluster"
node_container="$cluster-control-plane"
use_existing=0; keep=0; publish=0
for arg in "$@"; do
  case "$arg" in
    --use-existing) use_existing=1 ;;
    --keep-cluster) keep=1 ;;
    --publish-evidence) publish=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

have() { command -v "$1" >/dev/null 2>&1; }
for tool in docker kind kubectl node python3; do
  have "$tool" || { echo "not executed: $tool not found" >&2; exit 3; }
done
k() { kubectl --context "$ctx" "$@"; }

rm -rf "$out"
mkdir -p "$out"
cleanup() {
  if [ "$keep" = 0 ]; then kind delete cluster --name "$cluster" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

if [ "$use_existing" = 0 ]; then
  echo "== bring up kind + Calico"
  bash "$lab_root/cluster/up.sh" >"$out/cluster-up.log" 2>&1 || { tail -20 "$out/cluster-up.log"; exit 1; }
fi

if [ "$use_existing" = 1 ]; then
  echo "== reset lab state on the existing cluster"
  k delete ns lab-baseline lab-data lab-other lab-hardened lab-vap-only --ignore-not-found --wait=true >/dev/null
  k delete validatingadmissionpolicybinding,validatingadmissionpolicy lab-pod-extra-controls --ignore-not-found >/dev/null
  k delete clusterrolebinding,clusterrole lab-baseline-overreach --ignore-not-found >/dev/null
  docker exec "$node_container" rm -rf /var/lib/lab-host-canary
fi

echo "== versions"
{
  echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "kernel=$(uname -r)"
  echo "kind=$(kind version | awk '{print $2}')"
  k version -o json | python3 -c 'import json,sys; v=json.load(sys.stdin); print("kubectl=" + v["clientVersion"]["gitVersion"]); print("apiserver=" + v["serverVersion"]["gitVersion"])'
  k get nodes -o jsonpath='container_runtime={.items[0].status.nodeInfo.containerRuntimeVersion}{"\n"}'
  k -n kube-system get ds calico-node -o jsonpath='cni=calico {.spec.template.spec.containers[0].image}{"\n"}'
  have kyverno && echo "kyverno=$(kyverno version 2>/dev/null | awk '/Version/{print $2; exit}')" || echo "kyverno=not executed (not installed)"
  have opa && echo "opa=$(opa version | awk '/^Version/{print $2}')" || echo "opa=not executed (not installed)"
  have kubeconform && echo "kubeconform=$(kubeconform -v 2>&1 | head -1)" || echo "kubeconform=not executed (not installed)"
} | tee "$out/versions.txt"

echo "== NetworkPolicy enforcement smoke test (must pass before any network result is trusted)"
bash "$lab_root/scripts/np-smoke.sh" "$ctx" "$out/np-smoke.json" || { cat "$out/np-smoke.json"; echo "NetworkPolicy is NOT enforced by this cluster's CNI; network results would be meaningless" >&2; exit 1; }
cat "$out/np-smoke.json"

api_ip="$(k -n default get endpointslice -l kubernetes.io/service-name=kubernetes -o jsonpath='{.items[0].endpoints[0].addresses[0]}')"
echo "api server endpoint: $api_ip"

net() { # label deployment namespace binary target
  local result
  result="$(k -n "$3" exec "deploy/$2" -- "$4" tcpcheck "$5" 2>/dev/null || echo '{"connected":false,"error":"exec failed"}')"
  python3 -c 'import json,sys; print(json.dumps({"from": sys.argv[1], "to": sys.argv[2], "result": json.loads(sys.argv[3])}))' "$1" "$5" "$result"
}
can_i() { # serviceaccount-subject namespace-flag... ; prints yes/no
  k auth can-i "$@" 2>/dev/null || true
}
can_i_json() { # subject, then triples "verb resource [namespace]" via stdin lines
  local subject="$1" first=1
  printf '{'
  while read -r verb resource ns; do
    [ -n "$verb" ] || continue
    local ans label="$verb $resource"
    if [ -n "${ns:-}" ] && [ "$ns" != "-" ]; then
      ans="$(can_i "$verb" "$resource" -n "$ns" --as="$subject")"
      label="$label in $ns"
    else
      ans="$(can_i "$verb" "$resource" --as="$subject" --all-namespaces)"
      label="$label (any namespace)"
    fi
    [ "$first" = 1 ] || printf ', '
    first=0
    printf '"%s": %s' "$label" "$([ "$ans" = yes ] && echo true || echo false)"
  done
  printf '}\n'
}

echo "== BASELINE: apply insecure manifests"
k apply -f "$lab_root/baseline/00-namespaces.yaml" >/dev/null
# The admission cases name these ServiceAccounts, so they must exist for a pod to reach admission.
for sa in app api-reader; do k -n lab-baseline create serviceaccount "$sa" >/dev/null 2>&1 || true; done
k apply -f "$lab_root/baseline/10-rbac.yaml" -f "$lab_root/baseline/20-workload.yaml" -f "$lab_root/baseline/30-canaries.yaml" >/dev/null
k -n lab-baseline rollout status deploy/app --timeout=180s >/dev/null
k -n lab-data wait --for=condition=Ready pod/canary --timeout=120s >/dev/null
k -n lab-other wait --for=condition=Ready pod/neighbor --timeout=120s >/dev/null

echo "== BASELINE: workload identity, posture, reachability, admission"
k -n lab-baseline exec deploy/app -- posture k8sprobe >"$out/baseline-k8sprobe.json"
k -n lab-baseline exec deploy/app -- posture probe >"$out/baseline-posture.json"
{
  net baseline/app app lab-baseline posture "canary.lab-data.svc.cluster.local:9000"
  net baseline/app app lab-baseline posture "neighbor.lab-other.svc.cluster.local:9000"
  net baseline/app app lab-baseline posture "$api_ip:6443"
} >"$out/baseline-net.jsonl"
can_i_json "system:serviceaccount:lab-baseline:app-sa" >"$out/baseline-can-i.json" <<'LIST'
get secrets kube-system
list pods -
list nodes -
create pods/exec lab-data
create rolebindings lab-baseline
escalate clusterroles -
impersonate users -
LIST
k auth can-i --list --as=system:serviceaccount:lab-baseline:app-sa | tail -n +2 | wc -l | tr -d ' ' >"$out/baseline-can-i-rule-count.txt"
docker exec "$node_container" stat -c '%u %a %n' /var/lib/lab-host-canary/written-by-container.txt >"$out/baseline-hostpath-owner.txt"
(cd "$repo_root" && node "labs/kubernetes-security/scripts/admission-matrix.js" "$ctx" lab-baseline "$out/matrix-lab-baseline.json")

echo "== HARDENED: Pod Security Admission only (no ValidatingAdmissionPolicy yet)"
k apply -f "$lab_root/hardened/00-namespaces.yaml" -f "$lab_root/hardened/10-rbac.yaml" >/dev/null
(cd "$repo_root" && node "labs/kubernetes-security/scripts/admission-matrix.js" "$ctx" lab-hardened "$out/matrix-lab-hardened-psa.json")
# The baseline workload, submitted unchanged to the hardened namespace. PSA enforce
# applies to Pods, not Deployments: the Deployment is admitted (with a warning) and
# the ReplicaSet's pod creation is what gets refused. Record both halves.
python3 - "$lab_root/baseline/20-workload.yaml" >"$out/.baseline-in-hardened.yaml" <<'PY'
import sys, pathlib
text = pathlib.Path(sys.argv[1]).read_text().replace("namespace: lab-baseline", "namespace: lab-hardened").replace("serviceAccountName: app-sa", "serviceAccountName: app-sa")
print(text)
PY
k -n lab-hardened create serviceaccount app-sa >/dev/null 2>&1 || true
{
  echo "## kubectl apply --dry-run=server of the unchanged baseline Deployment into lab-hardened"
  k apply --dry-run=server -f "$out/.baseline-in-hardened.yaml" 2>&1 || true
  echo
  echo "## kubectl apply (persisted) and what the ReplicaSet controller experiences"
  k apply -f "$out/.baseline-in-hardened.yaml" 2>&1 || true
  sleep 12
  echo "pods_created_by_deployment=$(k -n lab-hardened get pods -l app=app --no-headers 2>/dev/null | wc -l | tr -d ' ')"
  k -n lab-hardened get events --field-selector reason=FailedCreate -o jsonpath='{range .items[*]}{.message}{"\n"}{end}' 2>&1 | head -3
} >"$out/hardened-rejects-baseline-workload.txt"
k -n lab-hardened delete deployment app --ignore-not-found --wait=true >/dev/null 2>&1 || true
k -n lab-hardened delete serviceaccount app-sa --ignore-not-found >/dev/null 2>&1 || true
rm -f "$out/.baseline-in-hardened.yaml"

echo "== HARDENED: add ValidatingAdmissionPolicy, then evaluate it in isolation and combined"
k apply -f "$lab_root/hardened/40-admission-vap.yaml" >/dev/null
k create namespace lab-vap-only >/dev/null 2>&1 || true
k label namespace lab-vap-only lab.example/admission=enforced --overwrite >/dev/null
# Same ServiceAccount definitions as lab-hardened so the two namespaces differ only in admission labels.
sed 's#namespace: lab-hardened#namespace: lab-vap-only#' "$lab_root/hardened/10-rbac.yaml" | k apply -f - >/dev/null
# The policy is compiled and bound asynchronously: wait until it denies a known gap.
for _ in $(seq 1 40); do
  if k -n lab-vap-only run vap-ready --image=busybox:1.37 --dry-run=server -o name >/dev/null 2>&1; then sleep 1; else break; fi
done
(cd "$repo_root" && node "labs/kubernetes-security/scripts/admission-matrix.js" "$ctx" lab-vap-only "$out/matrix-lab-vap-only.json")
(cd "$repo_root" && node "labs/kubernetes-security/scripts/admission-matrix.js" "$ctx" lab-hardened "$out/matrix-lab-hardened-combined.json")

echo "== HARDENED: network policies, then workloads"
sed "s#192.0.2.1/32#$api_ip/32#" "$lab_root/hardened/30-networkpolicies.yaml" | k apply -f - >/dev/null
k apply -f "$lab_root/hardened/20-workload.yaml" >/dev/null
k -n lab-hardened rollout status deploy/app --timeout=180s >/dev/null
k -n lab-hardened rollout status deploy/api-reader --timeout=180s >/dev/null
sleep 5
k -n lab-hardened exec deploy/app -- /app/posture k8sprobe >"$out/hardened-app-k8sprobe.json"
k -n lab-hardened exec deploy/api-reader -- /app/posture k8sprobe >"$out/hardened-apireader-k8sprobe.json"
k -n lab-hardened exec deploy/app -- /app/posture probe >"$out/hardened-posture.json"
{
  net hardened/app app lab-hardened /app/posture "canary.lab-data.svc.cluster.local:9000"
  net hardened/app app lab-hardened /app/posture "neighbor.lab-other.svc.cluster.local:9000"
  net hardened/app app lab-hardened /app/posture "$api_ip:6443"
  net hardened/api-reader api-reader lab-hardened /app/posture "canary.lab-data.svc.cluster.local:9000"
} >"$out/hardened-net.jsonl"
# Same baseline pod as before; only the data tier changed (ingress policy on lab-data).
net baseline/app app lab-baseline posture "canary.lab-data.svc.cluster.local:9000" >"$out/baseline-net-after-data-policy.jsonl"
can_i_json "system:serviceaccount:lab-hardened:api-reader" >"$out/hardened-apireader-can-i.json" <<'LIST'
get configmaps lab-hardened
list configmaps lab-hardened
list secrets lab-hardened
get secrets kube-system
create pods lab-hardened
list pods -
LIST
k -n lab-hardened auth can-i get configmap/app-config --as=system:serviceaccount:lab-hardened:api-reader >"$out/hardened-can-i-app-config.txt" 2>&1 || true
k -n lab-hardened auth can-i get configmap/unrelated-config --as=system:serviceaccount:lab-hardened:api-reader >"$out/hardened-can-i-unrelated-config.txt" 2>&1 || true
k auth can-i --list --as=system:serviceaccount:lab-hardened:api-reader -n lab-hardened | tail -n +2 | wc -l | tr -d ' ' >"$out/hardened-apireader-can-i-rule-count.txt"

echo "== offline engines on the same corpus"
if have kyverno; then
  (cd "$lab_root" && kyverno test . --remove-color) >"$out/kyverno-test.txt" 2>&1 || true
else
  echo "not executed: kyverno not installed" >"$out/kyverno-test.txt"
fi
if have opa; then
  opa test "$lab_root/policies/rego" >"$out/opa-unit-tests.txt" 2>&1 || true
  for set in baseline hardened; do
    node "$lab_root/scripts/manifests-to-input.js" "$lab_root/$set" >"$out/.in-$set.json"
    opa eval -d "$lab_root/policies/rego" -i "$out/.in-$set.json" 'data.lab.k8s.workload.deny' --format json >"$out/opa-$set.json"
  done
  node "$lab_root/scripts/manifests-to-input.js" "$lab_root/admission-cases/cases.yaml" >"$out/.in-cases.json"
  opa eval -d "$lab_root/policies/rego" -i "$out/.in-cases.json" 'data.lab.k8s.workload.pod_violations' --format json >"$out/opa-cases.json"
  rm -f "$out"/.in-*.json
else
  echo "not executed: opa not installed" >"$out/opa-unit-tests.txt"
fi
if have kubeconform; then
  kubeconform -strict -summary -ignore-missing-schemas -kubernetes-version "${KUBECONFORM_K8S_VERSION:-1.37.0}" \
    "$lab_root/baseline" "$lab_root/hardened" "$lab_root/admission-cases/cases.yaml" >"$out/kubeconform.txt" 2>&1 || true
else
  echo "not executed: kubeconform not installed" >"$out/kubeconform.txt"
fi

echo "== assertions on observed results"
python3 "$lab_root/tests/cluster_check.py" "$out" | tee "$out/assertions.txt"

if [ "$publish" = 1 ]; then
  python3 "$lab_root/scripts/publish_evidence.py" "$out" "$lab_root/evidence"
fi
