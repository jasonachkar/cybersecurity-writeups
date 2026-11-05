#!/usr/bin/env python3
"""Copy a sanitized subset of raw Kubernetes-lab output into the tracked evidence/ folder.

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
    "np-smoke.json",
    "baseline-k8sprobe.json",
    "baseline-posture.json",
    "baseline-net.jsonl",
    "baseline-net-after-data-policy.jsonl",
    "baseline-can-i.json",
    "baseline-can-i-rule-count.txt",
    "baseline-hostpath-owner.txt",
    "matrix-lab-baseline.json",
    "matrix-lab-hardened-psa.json",
    "matrix-lab-vap-only.json",
    "matrix-lab-hardened-combined.json",
    "hardened-rejects-baseline-workload.txt",
    "hardened-app-k8sprobe.json",
    "hardened-apireader-k8sprobe.json",
    "hardened-posture.json",
    "hardened-net.jsonl",
    "hardened-apireader-can-i.json",
    "hardened-can-i-app-config.txt",
    "hardened-can-i-unrelated-config.txt",
    "hardened-apireader-can-i-rule-count.txt",
    "kyverno-test.txt",
    "opa-unit-tests.txt",
    "opa-baseline.json",
    "opa-hardened.json",
    "opa-cases.json",
    "kubeconform.txt",
    "matrix.json",
    "matrix-table.txt",
]
host = socket.gethostname()
patterns = [
    (re.compile(r"/tmp/[A-Za-z0-9._-]+"), "<tmp>"),
    (re.compile(r"/home/[A-Za-z0-9._-]+/[^\s\"']*cybersecurity-writeups"), "<repo>"),
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
