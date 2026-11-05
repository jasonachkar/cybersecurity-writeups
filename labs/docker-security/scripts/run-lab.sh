#!/usr/bin/env bash
# Run the Docker security lab end to end on a LOCAL, DISPOSABLE Docker Engine.
#
#   bash labs/docker-security/scripts/run-lab.sh [--skip-supply-chain] [--publish-evidence]
#
# Needs: docker + compose v2, node, python3. Optional (recorded as "not executed"
# when missing): trivy, syft, cosign. Raw output goes to
# $LAB_OUT (default .artifacts/research/docker-security, git-ignored).
# --publish-evidence additionally copies a sanitized subset into evidence/.
#
# SAFETY: the insecure stack is run privileged with pid: host and the Docker
# socket mounted ON PURPOSE. Run this only on a throwaway VM or CI runner, never
# on a workstation or shared host. The probe binary only attempts the benign
# operations listed in app/main.go.
set -euo pipefail

lab_root="$(cd "$(dirname "$0")/.." && pwd)"
repo_root="$(cd "$lab_root/../.." && pwd)"
out="${LAB_OUT:-$repo_root/.artifacts/research/docker-security}"
skip_supply=0
publish=0
for arg in "$@"; do
  case "$arg" in
    --skip-supply-chain) skip_supply=1 ;;
    --publish-evidence) publish=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

have() { command -v "$1" >/dev/null 2>&1; }
if ! have docker || ! docker info >/dev/null 2>&1; then
  echo "not executed: no reachable Docker daemon" >&2
  exit 3
fi
docker compose version >/dev/null 2>&1 || { echo "not executed: docker compose v2 missing" >&2; exit 3; }

rm -rf "$out"
mkdir -p "$out/runtime" "$out/scan" "$out/sbom" "$out/signing"

canary="$(mktemp -d)"
printf 'CANARY-NOT-A-SECRET: lab marker\n' >"$canary/canary.txt"
chmod 0755 "$canary"
chmod 0644 "$canary/canary.txt"
export LAB_CANARY_DIR="$canary"

insecure=(docker compose -f "$lab_root/insecure/compose.yaml")
hardened=(docker compose -f "$lab_root/hardened/compose.yaml")
cleanup() {
  "${insecure[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  "${hardened[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$canary"
}
trap cleanup EXIT

echo "== environment"
{
  echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "kernel=$(uname -r)"
  docker info --format 'docker_server={{.ServerVersion}} cgroup_version={{.CgroupVersion}} security_options={{.SecurityOptions}} default_runtime={{.DefaultRuntime}} storage_driver={{.Driver}}'
  docker compose version --short | sed 's/^/compose=/'
  have trivy && echo "trivy=$(trivy --version | awk '/^Version/{print $2; exit}')" || echo "trivy=not executed (not installed)"
  have syft && echo "syft=$(syft version | awk '/^Version/{print $2}')" || echo "syft=not executed (not installed)"
  have cosign && echo "cosign=$(cosign version 2>/dev/null | awk '/GitVersion/{print $2}')" || echo "cosign=not executed (not installed)"
  have strace && echo "strace=$(strace -V | head -1)" || echo "strace=not installed (only needed to regenerate seccomp.json)"
} | tee "$out/versions.txt"

echo "== static policy gate (no Docker needed)"
# Run from the repository root with relative targets so no absolute path is
# recorded in the evidence.
lab_rel="${lab_root#"$repo_root"/}"
set +e
(cd "$repo_root" && node "$lab_rel/tests/policy-check.js" "$lab_rel/insecure") >"$out/runtime/static-insecure.txt"
echo $? >"$out/runtime/static-insecure.exit"
(cd "$repo_root" && node "$lab_rel/tests/policy-check.js" "$lab_rel/hardened") >"$out/runtime/static-hardened.txt"
echo $? >"$out/runtime/static-hardened.exit"
set -e
tail -n 1 "$out/runtime/static-insecure.txt" "$out/runtime/static-hardened.txt"

exec_json() { # compose-array-name, outfile, command...
  local -n stack=$1; local file=$2; shift 2
  "${stack[@]}" exec -T "$@" >"$file"
}
exec_code() { # compose-array-name, outfile-prefix, command...  (records exit code)
  local -n stack=$1; local prefix=$2; shift 2
  set +e
  "${stack[@]}" exec -T "$@" >"$prefix.out" 2>&1
  echo $? >"$prefix.exit"
  set -e
}

echo "== image attack-surface inventory (from the exported filesystem)"
for variant in insecure hardened; do
  cid="$(docker create "dockerlab/posture:$variant")"
  docker export "$cid" | python3 "$lab_root/tests/inventory.py" >"$out/runtime/$variant-inventory.json"
  docker rm "$cid" >/dev/null
done

echo "== insecure stack"
"${insecure[@]}" up -d --build >"$out/runtime/insecure-up.log" 2>&1
sleep 3
curl -fsS http://127.0.0.1:8080/healthz >"$out/runtime/insecure-published-port-healthz.txt"
exec_json insecure "$out/runtime/insecure-probe.json" -e PROBE_TCP_TARGET=canary:9000 app posture probe
exec_json insecure "$out/runtime/insecure-forktest.json" app posture forktest 200
exec_code insecure "$out/runtime/insecure-memtest" app posture memtest 512
mv "$out/runtime/insecure-memtest.out" "$out/runtime/insecure-memtest.log"
stat -c '%u %a %n' "$canary/written-by-container.txt" | sed "s#$canary#<canary-dir>#" >"$out/runtime/insecure-host-canary-owner.txt"
docker inspect dockerlab-insecure-app-1 --format '{{json .HostConfig}}' | python3 -c '
import json, sys
h = json.load(sys.stdin)
keys = ["Privileged", "PidMode", "ReadonlyRootfs", "CapAdd", "CapDrop", "SecurityOpt", "Memory", "PidsLimit", "NanoCpus", "PortBindings", "RestartPolicy"]
print(json.dumps({k: h.get(k) for k in keys}, indent=2, sort_keys=True))' >"$out/runtime/insecure-hostconfig.json"
"${insecure[@]}" down -v --remove-orphans >/dev/null 2>&1

echo "== hardened stack"
"${hardened[@]}" up -d --build >"$out/runtime/hardened-up.log" 2>&1
health=starting
for _ in $(seq 1 40); do
  health="$(docker inspect -f '{{.State.Health.Status}}' dockerlab-hardened-app-1 2>/dev/null || echo unknown)"
  [ "$health" = healthy ] && break
  sleep 1
done
echo "$health" >"$out/runtime/hardened-health-before.txt"
exec_json hardened "$out/runtime/hardened-probe.json" -e PROBE_TCP_TARGET=canary:9000 app /app/posture probe
exec_json hardened "$out/runtime/hardened-forktest.json" app /app/posture forktest 200
exec_code hardened "$out/runtime/hardened-memtest" app /app/posture memtest 512
mv "$out/runtime/hardened-memtest.out" "$out/runtime/hardened-memtest.log"
sleep 2
docker inspect -f '{{.State.Status}} oom_killed={{.State.OOMKilled}} health={{.State.Health.Status}}' dockerlab-hardened-app-1 >"$out/runtime/hardened-state-after-oom.txt"
docker inspect dockerlab-hardened-app-1 --format '{{json .HostConfig}}' | python3 -c '
import json, sys
h = json.load(sys.stdin)
keys = ["Privileged", "PidMode", "ReadonlyRootfs", "CapAdd", "CapDrop", "Memory", "MemorySwap", "PidsLimit", "NanoCpus", "PortBindings", "RestartPolicy"]
d = {k: h.get(k) for k in keys}
d["SecurityOpt"] = [o if not o.startswith("seccomp=") else "seccomp=<inlined profile, %d bytes>" % len(o) for o in h.get("SecurityOpt", [])]
print(json.dumps(d, indent=2, sort_keys=True))' >"$out/runtime/hardened-hostconfig.json"
"${hardened[@]}" down -v --remove-orphans >/dev/null 2>&1

echo "== seccomp attribution controls (same hardening, only seccomp varies)"
base=(--rm --user 65532:65532 --read-only --tmpfs "/tmp:rw,noexec,nosuid,nodev,size=8m,mode=1777" --cap-drop ALL --security-opt no-new-privileges)
docker run "${base[@]}" --security-opt seccomp=unconfined dockerlab/posture:hardened probe >"$out/runtime/hardened-seccomp-unconfined-probe.json"
docker run "${base[@]}" dockerlab/posture:hardened probe >"$out/runtime/hardened-seccomp-default-probe.json"
docker run "${base[@]}" --security-opt "seccomp=$lab_root/hardened/seccomp.json" dockerlab/posture:hardened probe >"$out/runtime/hardened-seccomp-custom-probe.json"

if [ "$skip_supply" = 0 ]; then
  echo "== scan, SBOM, local signing"
  bash "$lab_root/scripts/scan.sh" "$out" >"$out/scan/scan-run.log" 2>&1 || echo "scan.sh failed; see $out/scan/scan-run.log"
  bash "$lab_root/scripts/sign-verify.sh" "$out" >"$out/signing/sign-run.log" 2>&1 || echo "sign-verify.sh failed; see $out/signing/sign-run.log"
else
  echo "== supply chain skipped by flag"
fi

echo "== assertions on observed results"
python3 "$lab_root/tests/runtime_check.py" "$out" | tee "$out/assertions.txt"

if [ "$publish" = 1 ]; then
  python3 "$lab_root/scripts/publish_evidence.py" "$out" "$lab_root/evidence"
fi
