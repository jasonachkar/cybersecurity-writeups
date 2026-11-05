#!/usr/bin/env bash
# Local-only image signing and verification with cosign. Usage: sign-verify.sh <outdir>
#
# Everything is local and disposable: a registry:2 container on loopback, an
# ephemeral key pair generated into a temp directory with a random one-time
# password, and a signing config that lists NO Fulcio/Rekor/TSA services.
# Consequences (stated in the README): there is no transparency log, no identity
# binding and no public non-repudiation. This proves the verify-by-digest
# mechanics, not a production trust root.
set -euo pipefail

out="${1:?usage: sign-verify.sh <outdir>}"
mkdir -p "$out/signing"
log="$out/signing/signing-log.txt"
: >"$log"

have() { command -v "$1" >/dev/null 2>&1; }
if ! have cosign; then
  printf '{"executed": false, "tool": "cosign", "reason": "binary not found on PATH"}\n' >"$out/signing/status.json"
  echo "not executed: cosign (binary not found on PATH)"
  exit 0
fi

work="$(mktemp -d)"
registry_name="dockerlab-registry"
port="${LAB_REGISTRY_PORT:-5001}"
cleanup() {
  docker rm -f "$registry_name" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

step() { printf '\n## %s\n' "$*" | tee -a "$log"; }
declare -A result

# registry:2 pinned by the index digest observed locally.
docker rm -f "$registry_name" >/dev/null 2>&1 || true
docker run -d --name "$registry_name" -p "127.0.0.1:$port:5000" \
  registry:2@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373 >/dev/null
for _ in $(seq 1 30); do curl -fs "http://127.0.0.1:$port/v2/" >/dev/null 2>&1 && break; sleep 0.2; done

repo="127.0.0.1:$port/dockerlab/posture"
accept='application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'
digest_of() { # tag -> sha256:...
  curl -fsI -H "Accept: $accept" "http://127.0.0.1:$port/v2/dockerlab/posture/manifests/$1" \
    | tr -d '\r' | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2}'
}

step "push images to the local registry"
for variant in hardened insecure; do
  docker tag "dockerlab/posture:$variant" "$repo:$variant"
  docker push -q "$repo:$variant" >>"$log"
done
hardened_digest="$(digest_of hardened)"
insecure_digest="$(digest_of insecure)"
echo "hardened=$hardened_digest insecure=$insecure_digest" | tee -a "$log"

step "generate ephemeral key pair (one-time random password, never written to disk)"
COSIGN_PASSWORD="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
export COSIGN_PASSWORD
(cd "$work" && cosign generate-key-pair >/dev/null 2>&1)
mkdir "$work/other"
(cd "$work/other" && COSIGN_PASSWORD="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')" cosign generate-key-pair >/dev/null 2>&1)
cosign signing-config create --out "$work/local-signing-config.json" >/dev/null
echo "signing config (no Fulcio, Rekor or TSA services):" | tee -a "$log"
cat "$work/local-signing-config.json" | tee -a "$log"

verify() { cosign verify --key "$1" --insecure-ignore-tlog=true "$2" >>"$log" 2>&1; }

step "sign the hardened image by digest"
cosign sign --key "$work/cosign.key" --signing-config "$work/local-signing-config.json" --yes \
  "$repo@$hardened_digest" >>"$log" 2>&1
result[signed]=true

step "verify hardened digest with the right key (expect success)"
if verify "$work/cosign.pub" "$repo@$hardened_digest"; then result[verify_signed_digest]=true; else result[verify_signed_digest]=false; fi

step "verify the unsigned insecure digest (expect rejection)"
if verify "$work/cosign.pub" "$repo@$insecure_digest"; then result[unsigned_rejected]=false; else result[unsigned_rejected]=true; fi

step "verify the hardened digest with an unrelated key (expect rejection)"
if verify "$work/other/cosign.pub" "$repo@$hardened_digest"; then result[wrong_key_rejected]=false; else result[wrong_key_rejected]=true; fi

step "tag substitution: point the signed tag at different content, verify by tag (expect rejection)"
docker tag "dockerlab/posture:hardened" "$repo:release"
docker push -q "$repo:release" >>"$log"
if verify "$work/cosign.pub" "$repo:release"; then result[tag_before_substitution_ok]=true; else result[tag_before_substitution_ok]=false; fi
docker tag "dockerlab/posture:insecure" "$repo:release"
docker push -q "$repo:release" >>"$log"
if verify "$work/cosign.pub" "$repo:release"; then result[tag_substitution_rejected]=false; else result[tag_substitution_rejected]=true; fi

if [ -f "$out/sbom/hardened.cdx.json" ]; then
  step "attach the SBOM as a signed attestation, then verify it"
  cosign attest --key "$work/cosign.key" --signing-config "$work/local-signing-config.json" --yes \
    --type cyclonedx --predicate "$out/sbom/hardened.cdx.json" "$repo@$hardened_digest" >>"$log" 2>&1
  if cosign verify-attestation --key "$work/cosign.pub" --insecure-ignore-tlog=true --type cyclonedx \
      "$repo@$hardened_digest" >>"$log" 2>&1; then result[attestation_verified]=true; else result[attestation_verified]=false; fi
  if cosign verify-attestation --key "$work/cosign.pub" --insecure-ignore-tlog=true --type slsaprovenance \
      "$repo@$hardened_digest" >>"$log" 2>&1; then result[wrong_predicate_rejected]=false; else result[wrong_predicate_rejected]=true; fi
else
  echo "SBOM not generated (syft missing): attestation steps not executed" | tee -a "$log"
fi

{
  printf '{\n  "executed": true,\n  "cosign": "%s",\n  "hardened_digest": "%s",\n  "insecure_digest": "%s",\n' \
    "$(cosign version 2>/dev/null | awk '/GitVersion/{print $2}')" "$hardened_digest" "$insecure_digest"
  printf '  "transparency_log": "not used (signing config lists no Rekor service; verify ran with --insecure-ignore-tlog)",\n'
  printf '  "results": {'
  sep=""
  for key in "${!result[@]}"; do printf '%s"%s": %s' "$sep" "$key" "${result[$key]}"; sep=", "; done
  printf '}\n}\n'
} >"$out/signing/summary.json"
cat "$out/signing/summary.json"
