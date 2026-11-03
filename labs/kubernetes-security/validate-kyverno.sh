#!/usr/bin/env bash
# Download the reviewed CLI asset, verify its fixed release checksum, test locally.
set -euo pipefail
lab_root="$(cd "$(dirname "$0")" && pwd)"
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) asset=darwin_arm64; digest=cc69bc6638da1993146c134943fac91cbc9dd0ce60a3e88c6d7c518ae00f1abc ;;
  Darwin-x86_64) asset=darwin_x86_64; digest=a461096a3111e6a4134c2bd135ddd8e0bfd9d466a5d5b17810b76a484fffdae4 ;;
  Linux-aarch64|Linux-arm64) asset=linux_arm64; digest=160345e172de877db9d7d237d26bf3357943e74d77ced1ba5b08cef1276f1084 ;;
  Linux-x86_64) asset=linux_x86_64; digest=cb2feb8356149fd2fe774c894ccf0969f4a60a83867dd913af724f74ffbbc18b ;;
  *) echo 'Use the official Kyverno 1.18.2 CLI for this platform.' >&2; exit 2 ;;
esac
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
curl --fail --location --silent --show-error \
  "https://github.com/kyverno/kyverno/releases/download/v1.18.2/kyverno-cli_v1.18.2_${asset}.tar.gz" \
  -o "$work/kyverno.tar.gz"
python3 - "$work/kyverno.tar.gz" "$digest" <<'PY'
import hashlib
import pathlib
import sys
actual = hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest()
if actual != sys.argv[2]:
    raise SystemExit("Kyverno asset checksum mismatch")
print("PASS: Kyverno 1.18.2 asset matches the reviewed release checksum")
PY
tar -xzf "$work/kyverno.tar.gz" -C "$work" kyverno
"$work/kyverno" test "$lab_root" --remove-color
