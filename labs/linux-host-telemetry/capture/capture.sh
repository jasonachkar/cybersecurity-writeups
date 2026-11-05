#!/usr/bin/env bash
# Capture REAL kernel-observed syscalls from a throwaway container and normalize them.
#   bash capture/capture.sh <outdir>      needs: docker, strace (root), python3
# Output: <outdir>/strace.txt (raw) and <outdir>/capture-events.jsonl (normalized).
# The container runs capture/workload.sh: harmless analogs of the behaviours the rules
# look for, confined to the container's own filesystem and the default bridge network.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="${1:?usage: capture.sh <outdir>}"
mkdir -p "$out"

for tool in docker strace python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "not executed: $tool not found" >&2; exit 3; }
done

cleanup() { docker rm -f lab-canary lab-trace >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

docker run -d --name lab-canary busybox:1.37 \
  sh -c 'mkdir -p /www && echo canary > /www/index.html && exec httpd -f -p 9000 -h /www' >/dev/null
canary_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' lab-canary)"

docker create --name lab-trace -e "CANARY=$canary_ip" -v "$here/workload.sh:/workload.sh:ro" \
  busybox:1.37 sh /workload.sh >/dev/null
docker start lab-trace >/dev/null
pid="$(docker inspect -f '{{.State.Pid}}' lab-trace)"
root_exe="$(readlink "/proc/$pid/exe")"

# strace exits when the traced container process exits.
strace -f -ttt -qq -s 256 \
  -e trace=execve,openat,open,clone,clone3,fork,vfork,chmod,fchmodat,truncate,unlink,unlinkat,connect \
  -p "$pid" -o "$out/strace.txt" || true

python3 "$here/normalize_strace.py" "$out/strace.txt" "$root_exe" "$out/capture-events.jsonl"
{
  echo "strace=$(strace -V | head -1)"
  echo "container_image=busybox:1.37"
  echo "root_exe=$root_exe"
  echo "canary_network_class=private"
} >"$out/capture-meta.txt"
