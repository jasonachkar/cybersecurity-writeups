#!/usr/bin/env python3
"""Copy a sanitized subset of raw lab output into the tracked evidence/ folder.

Usage: publish_evidence.py <raw-outdir> <evidence-dir>

Raw output lives in the git-ignored .artifacts/research/ tree. Only the files the
README cites are copied. Sanitizing is conservative: temp directory names, the
host's hostname and any 64-hex container IDs that are not part of a sha256:
digest are replaced, and file contents are never rewritten otherwise.
"""
import pathlib
import re
import shutil
import socket
import sys

raw, dest = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
KEEP = [
    "versions.txt",
    "assertions.txt",
    "runtime/static-insecure.txt",
    "runtime/static-hardened.txt",
    "runtime/insecure-probe.json",
    "runtime/hardened-probe.json",
    "runtime/insecure-inventory.json",
    "runtime/hardened-inventory.json",
    "runtime/insecure-hostconfig.json",
    "runtime/hardened-hostconfig.json",
    "runtime/insecure-forktest.json",
    "runtime/hardened-forktest.json",
    "runtime/insecure-memtest.exit",
    "runtime/hardened-memtest.exit",
    "runtime/hardened-memtest.log",
    "runtime/hardened-state-after-oom.txt",
    "runtime/insecure-host-canary-owner.txt",
    "runtime/hardened-seccomp-unconfined-probe.json",
    "runtime/hardened-seccomp-default-probe.json",
    "runtime/hardened-seccomp-custom-probe.json",
    "scan/summary.json",
    "sbom/status.json",
    "scan/status.json",
    "signing/summary.json",
    "signing/signing-log.txt",
    "signing/status.json",
]
host = socket.gethostname()
patterns = [
    (re.compile(r"/tmp/[A-Za-z0-9._-]+"), "<tmp>"),
    (re.compile(r"(?<!sha256:)\b[0-9a-f]{64}\b"), "<id>"),
]

dest.mkdir(parents=True, exist_ok=True)
for existing in dest.iterdir():
    # observation-* files are one-off records that cannot be regenerated.
    if existing.is_file() and not existing.name.startswith("observation-"):
        existing.unlink()
copied = 0
for rel in KEEP:
    src = raw / rel
    if not src.exists():
        continue
    text = src.read_text(errors="replace")
    if host:
        text = text.replace(host, "<host>")
    for pattern, repl in patterns:
        text = pattern.sub(repl, text)
    name = rel.replace("/", "__")
    (dest / name).write_text(text)
    copied += 1
print(f"copied {copied} sanitized evidence files to {dest}")
