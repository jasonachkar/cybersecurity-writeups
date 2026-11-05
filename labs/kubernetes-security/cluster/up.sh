#!/usr/bin/env bash
# Create the lab cluster: kind + Calico (policy-enforcing CNI) + preloaded images.
#   bash labs/kubernetes-security/cluster/up.sh
# Needs: docker, kind, kubectl, curl, sha256sum. Creates ONLY a local kind cluster
# named $LAB_CLUSTER (default k8s-sec-lab). Never touches an existing kubeconfig
# context other than the one kind creates for it.
set -euo pipefail

lab_root="$(cd "$(dirname "$0")/.." && pwd)"
cluster="${LAB_CLUSTER:-k8s-sec-lab}"
calico_version="v3.33.0"
# SHA-256 of manifests/calico.yaml at that tag, recorded when the lab was built.
# This detects a changed file; it is not a signature check.
calico_sha256="$(cat "$lab_root/cluster/calico.sha256")"

for tool in docker kind kubectl curl sha256sum; do
  command -v "$tool" >/dev/null || { echo "missing: $tool" >&2; exit 2; }
done

# Pick the config: portable unless told otherwise or the host needs the accommodations.
config="$lab_root/cluster/kind-config.yaml"
cgroup_fs="$(stat -fc %T /sys/fs/cgroup 2>/dev/null || echo unknown)"
cap_bnd="$(awk '/^CapBnd/{print $2}' /proc/self/status)"
if [ "${LAB_KIND_COMPAT:-auto}" = 1 ] || { [ "${LAB_KIND_COMPAT:-auto}" = auto ] && { [ "$cgroup_fs" != cgroup2fs ] || [ $(( 0x$cap_bnd >> 24 & 1 )) = 0 ]; }; }; then
  config="$lab_root/cluster/kind-config.compat.yaml"
fi
echo "kind config: ${config#"$lab_root"/} (cgroup fs: $cgroup_fs, CapBnd: $cap_bnd)"

kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
kind create cluster --name "$cluster" --config "$config" --wait 0s

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
curl -fsSL -o "$work/calico.yaml" "https://raw.githubusercontent.com/projectcalico/calico/$calico_version/manifests/calico.yaml"
echo "$calico_sha256  $work/calico.yaml" | sha256sum -c -

# Images are pre-loaded because the kind node may have no registry egress. A
# single-platform archive avoids multi-platform index errors with Docker's
# containerd image store. If quay.io is unreachable, the same Calico images on
# Docker Hub are retagged to the name the manifest expects.
load() { # image
  docker save --platform linux/amd64 -o "$work/img.tar" "$1"
  kind load image-archive "$work/img.tar" --name "$cluster"
}
# Prefer an image already in the local cache; otherwise pull with retry/backoff
# (Docker Hub anonymous pulls are rate limited and answer HTTP 429 when exhausted).
pull_retry() { # ref
  local attempt
  for attempt in 1 2 3 4; do
    docker pull -q "$1" >/dev/null 2>&1 && return 0
    sleep $((attempt * attempt * 3))
  done
  return 1
}
for component in calico node third-party-cni-plugins; do
  ref="quay.io/calico/$component:$calico_version"
  mirror="docker.io/calico/$component:$calico_version"
  if docker image inspect "$ref" >/dev/null 2>&1; then :
  elif docker image inspect "$mirror" >/dev/null 2>&1; then docker tag "$mirror" "$ref"
  elif docker pull -q "$ref" >/dev/null 2>&1; then :
  elif pull_retry "$mirror"; then docker tag "$mirror" "$ref"
  else echo "cannot obtain $ref or $mirror" >&2; exit 1
  fi
  load "$ref"
done
for image in busybox:1.37 dockerlab/posture:insecure dockerlab/posture:hardened; do
  docker image inspect "$image" >/dev/null 2>&1 || { echo "image $image missing: run labs/docker-security/scripts/run-lab.sh first (or: docker compose -f labs/docker-security/{insecure,hardened}/compose.yaml build)" >&2; exit 2; }
  load "$image"
done

kubectl --context "kind-$cluster" apply -f "$work/calico.yaml" >/dev/null
kubectl --context "kind-$cluster" -n kube-system rollout status ds/calico-node --timeout=300s
kubectl --context "kind-$cluster" -n kube-system wait --for=condition=Ready pod -l k8s-app=kube-dns --timeout=300s
kubectl --context "kind-$cluster" wait --for=condition=Ready node --all --timeout=120s
echo "cluster $cluster ready"
