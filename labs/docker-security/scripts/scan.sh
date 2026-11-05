#!/usr/bin/env bash
# Scan both lab images, generate SBOMs, and summarize. Usage: scan.sh <outdir>
# Needs the images dockerlab/posture:{insecure,hardened} to exist locally.
# trivy and syft are optional: a missing tool is recorded as "not executed".
# Network: trivy downloads its vulnerability DB (OCI artifact) on first use; run
# with TRIVY_SKIP_DB_UPDATE=true and a populated TRIVY_CACHE_DIR to stay offline.
set -euo pipefail

lab_root="$(cd "$(dirname "$0")/.." && pwd)"
out="${1:?usage: scan.sh <outdir>}"
mkdir -p "$out/scan" "$out/sbom"
work="$(mktemp -d)"
cleanup() { rm -rf "$work"; }
trap cleanup EXIT
export TRIVY_CACHE_DIR="${TRIVY_CACHE_DIR:-$work/trivy-cache}"

have() { command -v "$1" >/dev/null 2>&1; }
not_executed() { # file, tool, reason
  printf '{"executed": false, "tool": "%s", "reason": "%s"}\n' "$2" "$3" >"$1"
  echo "not executed: $2 ($3)"
}

if ! have trivy; then
  not_executed "$out/scan/status.json" trivy "binary not found on PATH"
fi
if have syft; then
  syft version -o json >"$out/sbom/syft-version.json" 2>/dev/null || syft version >"$out/sbom/syft-version.txt"
else
  not_executed "$out/sbom/status.json" syft "binary not found on PATH"
fi

for variant in insecure hardened; do
  # A single-platform archive avoids multi-platform index issues with the
  # containerd image store.
  docker save --platform linux/amd64 -o "$work/$variant.tar" "dockerlab/posture:$variant"
  if have trivy; then
    trivy image --input "$work/$variant.tar" --scanners vuln --format json -q \
      -o "$out/scan/trivy-$variant.json"
  fi
  if have syft; then
    syft "docker-archive:$work/$variant.tar" -q -o "cyclonedx-json=$out/sbom/$variant.cdx.json"
    if have trivy; then
      # SBOM -> vulnerability match without the image: the artifact a registry or
      # admission controller can hold when it cannot pull layers.
      trivy sbom "$out/sbom/$variant.cdx.json" --format json -q -o "$out/scan/trivy-sbom-$variant.json"
    fi
  fi
done

if have trivy; then
  # Recorded after the scans so the vulnerability DB timestamps are populated.
  trivy version --format json >"$out/scan/trivy-version.json"
  # Dockerfile misconfiguration checks bundled with the binary (no download).
  for variant in insecure hardened; do
    trivy config "$lab_root/$variant" --format json -q -o "$out/scan/trivy-config-$variant.json"
  done
fi

python3 "$lab_root/tests/summarize_scan.py" "$out" >"$out/scan/summary.json"
cat "$out/scan/summary.json"
