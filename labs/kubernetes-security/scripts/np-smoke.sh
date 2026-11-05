#!/usr/bin/env bash
# Does this cluster's CNI actually ENFORCE NetworkPolicy? Usage: np-smoke.sh <context> [outfile]
#
# A NetworkPolicy object is accepted by the API server whether or not anything
# enforces it. This test must pass before any "blocked" result in the lab means
# anything. It creates a throwaway namespace and deletes it afterwards.
set -euo pipefail
ctx="${1:?usage: np-smoke.sh <kube-context> [outfile]}"
outfile="${2:-/dev/stdout}"
k() { kubectl --context "$ctx" "$@"; }
ns=np-smoke
cleanup() { k delete ns "$ns" --wait=false >/dev/null 2>&1 || true; }
trap cleanup EXIT

k delete ns "$ns" --wait=true >/dev/null 2>&1 || true
k create ns "$ns" >/dev/null
k -n "$ns" apply -f - >/dev/null <<'YAML'
apiVersion: v1
kind: Pod
metadata: {name: server, labels: {app: server}}
spec:
  automountServiceAccountToken: false
  containers:
    - name: s
      image: busybox:1.37
      imagePullPolicy: IfNotPresent
      command: ["sh", "-c", "mkdir -p /www && echo ok > /www/index.html && exec httpd -f -p 8080 -h /www"]
---
apiVersion: v1
kind: Pod
metadata: {name: client, labels: {app: client}}
spec:
  automountServiceAccountToken: false
  containers:
    - name: c
      image: busybox:1.37
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
YAML
k -n "$ns" wait --for=condition=Ready pod/server pod/client --timeout=120s >/dev/null
server_ip="$(k -n "$ns" get pod server -o jsonpath='{.status.podIP}')"

reach() { k -n "$ns" exec client -- wget -q -T 3 -O /dev/null "http://$server_ip:8080" >/dev/null 2>&1 && echo true || echo false; }
before="$(reach)"
k -n "$ns" apply -f - >/dev/null <<'YAML'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: default-deny}
spec: {podSelector: {}, policyTypes: [Ingress, Egress]}
YAML
sleep 6
after="$(reach)"
enforced=false
if [ "$before" = true ] && [ "$after" = false ]; then enforced=true; fi
printf '{"before_policy_reachable": %s, "after_default_deny_reachable": %s, "networkpolicy_enforced": %s}\n' "$before" "$after" "$enforced" >"$outfile"
[ "$enforced" = true ]
