#!/usr/bin/env bash
# Run the Linux host-telemetry detection lab.
#   bash labs/linux-host-telemetry/scripts/run-lab.sh [--publish-evidence]
# Always: generate the synthetic corpus, run the nine rules, score them, run the unit tests.
# If docker and strace (root) are available: also capture REAL syscalls from a throwaway
# container and run the same rules over them. Otherwise that part is "not executed".
# Raw output: $LAB_OUT (default .artifacts/research/linux-host-telemetry, git-ignored).
set -euo pipefail

lab_root="$(cd "$(dirname "$0")/.." && pwd)"
repo_root="$(cd "$lab_root/../.." && pwd)"
out="${LAB_OUT:-$repo_root/.artifacts/research/linux-host-telemetry}"
publish=0
[ "${1:-}" = "--publish-evidence" ] && publish=1
rm -rf "$out"
mkdir -p "$out"

{
  echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "python=$(python3 --version | awk '{print $2}')"
  echo "sqlite=$(python3 -c 'import sqlite3; print(sqlite3.sqlite_version)')"
  echo "kernel=$(uname -r)"
  command -v strace >/dev/null 2>&1 && echo "strace=$(strace -V | head -1)" || echo "strace=not executed (not installed)"
  command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && echo "docker=$(docker version -f '{{.Server.Version}}')" || echo "docker=not executed (no daemon)"
} | tee "$out/versions.txt"

echo "== unit tests"
python3 -I "$lab_root/tests/test_detections.py" >"$out/unit-tests.txt" 2>&1 || { tail -20 "$out/unit-tests.txt"; exit 1; }
tail -3 "$out/unit-tests.txt"

echo "== synthetic corpus"
python3 "$lab_root/generator.py" --out "$out/events.jsonl" --scenarios "$out/scenarios.json" 2>&1 | tee "$out/generator.txt"
python3 "$lab_root/engine.py" --events "$out/events.jsonl" --scenarios "$out/scenarios.json" --json >"$out/engine-synthetic.json"
# The same corpus with the network sensor removed: rules that need it must say "blind".
python3 "$lab_root/engine.py" --events "$out/events.jsonl" --scenarios "$out/scenarios.json" --sources exec,file --json >"$out/engine-blind-net.json"
# Count synthetic-flagged events for the evidence record.
python3 - "$out" <<'PY'
import json, sys
out = sys.argv[1]
for name in ("engine-synthetic.json",):
    data = json.load(open(f"{out}/{name}"))
    events = [json.loads(l) for l in open(f"{out}/events.jsonl")]
    data["synthetic_events"] = sum(1 for e in events if e["synthetic"] is True)
    json.dump(data, open(f"{out}/{name}", "w"), indent=2, sort_keys=True)
PY

echo "== real-kernel capture (strace in a throwaway container)"
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && command -v strace >/dev/null 2>&1; then
  mkdir -p "$out/capture"
  bash "$lab_root/capture/capture.sh" "$out/capture"
  python3 "$lab_root/engine.py" --events "$out/capture/capture-events.jsonl" --json >"$out/engine-capture.json"
  python3 - "$out" <<'PY'
import json, sys
out = sys.argv[1]
data = json.load(open(f"{out}/engine-capture.json"))
events = [json.loads(l) for l in open(f"{out}/capture/capture-events.jsonl")]
data["synthetic_events"] = sum(1 for e in events if e["synthetic"] is True)
json.dump(data, open(f"{out}/engine-capture.json", "w"), indent=2, sort_keys=True)
PY
else
  echo "not executed: docker daemon or strace unavailable" | tee "$out/capture-status.txt"
fi

echo "== assertions"
python3 "$lab_root/scripts/summarize.py" "$out" | tee "$out/assertions.txt"

if [ "$publish" = 1 ]; then
  ev="$lab_root/evidence"
  mkdir -p "$ev"
  find "$ev" -maxdepth 1 -type f -delete
  for f in versions.txt assertions.txt summary.txt scenarios.json engine-synthetic.json engine-blind-net.json engine-capture.json generator.txt; do
    [ -f "$out/$f" ] && cp "$out/$f" "$ev/$f"
  done
  if [ -d "$out/capture" ]; then
    cp "$out/capture/capture-meta.txt" "$out/capture/strace.txt" "$out/capture/capture-events.jsonl" "$ev/"
  fi
  echo "evidence copied to ${ev#"$repo_root"/}"
fi
