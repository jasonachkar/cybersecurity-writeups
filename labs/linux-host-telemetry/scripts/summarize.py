#!/usr/bin/env python3
"""Summarize engine output and assert the lab's claims. Usage: summarize.py <outdir>

Writes <outdir>/summary.txt and exits nonzero if an observed result differs from the
documented one. Scenario-level precision/recall describe THIS synthetic corpus, which
the rule author wrote; they are a regression guard, not an estimate of field accuracy.
"""
import json
import pathlib
import sys

out = pathlib.Path(sys.argv[1])
syn = json.loads((out / "engine-synthetic.json").read_text())
blind = json.loads((out / "engine-blind-net.json").read_text())
failures = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else f"  {detail}"))
    if not ok:
        failures.append(name)


rows = ["| Rule | TP | FP | FN | TN | Precision | Recall |", "| --- | --- | --- | --- | --- | --- | --- |"]
for rid, c in sorted(syn["confusion"].items()):
    p = f"{c['TP'] / (c['TP'] + c['FP']):.2f}" if c["TP"] + c["FP"] else "n/a"
    r = f"{c['TP'] / (c['TP'] + c['FN']):.2f}" if c["TP"] + c["FN"] else "n/a"
    rows.append(f"| {rid} | {c['TP']} | {c['FP']} | {c['FN']} | {c['TN']} | {p} | {r} |")
lat = sorted(a["synthetic_latency_seconds"] for a in syn["alerts"])
summary = [f"Synthetic corpus: {syn['events']} events, {len(syn['alerts'])} deduplicated alerts, {syn['background_alerts']} alerts on background noise.", "", *rows, "",
           f"Synthetic detection latency (event time to batch-evaluation time, seconds): min {lat[0]}, median {lat[len(lat) // 2]}, max {lat[-1]}. "
           "These are synthetic clocks, not measured latency."]

check("synthetic corpus: every outcome matches its documented expectation", syn["unexpected_outcomes"] == [], syn["unexpected_outcomes"])
check("synthetic corpus: background noise produced no alerts", syn["background_alerts"] == 0)
check("synthetic corpus: all nine rules were evaluated", all(v["status"] == "evaluated" for v in syn["coverage"].values()))
check("missing network source: LNX-004 is reported blind", blind["coverage"]["LNX-004"]["status"] == "blind")
check("missing network source: no LNX-004 alert and no score for it", not [a for a in blind["alerts"] if a["rule"] == "LNX-004"]
      and sum(blind["confusion"]["LNX-004"][k] for k in ("TP", "FP", "FN", "TN")) == 0)

cap_path = out / "engine-capture.json"
if cap_path.exists():
    cap = json.loads(cap_path.read_text())
    fired = sorted({a["rule"] for a in cap["alerts"]})
    check("real capture: exactly the five designed analogs alert", fired == ["LNX-002", "LNX-005", "LNX-006", "LNX-007", "LNX-009"], fired)
    check("real capture: the private-address connect from /tmp stays silent (LNX-004 negative control)", "LNX-004" not in fired)
    check("real capture: LNX-003 is blind because strace cannot supply ExecStart", cap["coverage"]["LNX-003"]["status"] == "blind"
          and cap["coverage"]["LNX-003"]["missing_fields"] == ["exec_start"])
    check("real capture: no event is flagged synthetic", cap["synthetic_events"] == 0)
    summary += ["", f"Real-kernel capture: {cap['events']} events from strace, alerts from {', '.join(fired)}; LNX-003 blind (no ExecStart)."]
else:
    print("SKIP  real capture: strace/docker not available (see capture-status.txt)")
    summary += ["", "Real-kernel capture: not executed."]

(out / "summary.txt").write_text("\n".join(summary) + "\n")
print(f"\n{len(failures)} failed")
sys.exit(1 if failures else 0)
