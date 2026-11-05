---
id: linux-host-telemetry
title: Linux host telemetry detection lab
navTitle: Linux host telemetry
domain: linux-security
order: 130
summary: Runs nine SQL detection rules over a deterministic synthetic corpus with labeled benign look-alikes and known evasions, then over real syscalls captured with strace from a throwaway container.
implementationStatus: partially-tested
related:
  research: [host-telemetry-detection-lab, evidence-driven-host-analysis]
sourceFiles:
  - { path: labs/linux-host-telemetry/engine.py, label: Detection engine, language: python, primary: true }
  - { path: labs/linux-host-telemetry/generator.py, label: Synthetic corpus generator, language: python }
  - { path: labs/linux-host-telemetry/rules/lnx-001-service-spawns-shell.sql, label: LNX-001 service spawns shell, language: sql }
  - { path: labs/linux-host-telemetry/rules/lnx-006-privileged-config-change.sql, label: LNX-006 privileged config change, language: sql }
  - { path: labs/linux-host-telemetry/capture/normalize_strace.py, label: strace normalizer, language: python }
  - { path: labs/linux-host-telemetry/allowlist.json, label: Allowlist with owner and expiry, language: json }
  - { path: labs/linux-host-telemetry/tests/test_detections.py, label: Tests, language: python }
runCommands:
  - python3 labs/linux-host-telemetry/tests/test_detections.py
  - bash labs/linux-host-telemetry/scripts/run-lab.sh
---

# Linux host telemetry detection lab

**Status: partially tested.** The engine, the nine rules and the 23 unit tests run anywhere with Python 3 and are part of
`npm run validate`. The real-kernel capture ran once on 2026-11-05 on a disposable VM and is not in CI. The analysis,
false-positive reasoning, response actions and diagrams are in the article:
[Host Telemetry Detection Lab](../../linux-security/host-telemetry-detection-lab.md).

> **Every event the generator produces is synthetic.** Nothing in this lab records, simulates or reproduces a real
> intrusion. Events are data: a path, an executable name, a destination in a documentation address range. No malicious code
> exists here, no payload is executed, and the real-kernel capture runs only harmless placeholders inside a throwaway container.

Evidence labels: `tested locally` (executed here, output in [`evidence/`](https://github.com/jasonachkar/cybersecurity-writeups/tree/main/labs/linux-host-telemetry/evidence)),
`policy model` (a rule evaluated by a local test, not by a production sensor), `source-reviewed`, `requires-review`.

## Scope

Detection **logic** over host telemetry: process ancestry, file writes, file reads, permission changes and outbound connections.
Not in scope: collecting telemetry at fleet scale, kernel sensors (auditd, eBPF, Falco, Tetragon), a SIEM, enrichment, or any response
automation. Rules are tested on labeled data the rule author wrote, so the numbers describe the rules' behaviour on that corpus, not how they
would perform on a real fleet.

## What I built

| Path | Purpose |
| --- | --- |
| `generator.py` | Deterministic (seeded) synthetic corpus: 855 events in 42 labeled scenarios; every event has `"synthetic": true` |
| `engine.py` | Loads events into SQLite, validates the schema, runs `rules/*.sql`, applies the allowlist, deduplicates, reports missing sources and fields as **blind**, scores against labels |
| `rules/` | Nine rules, each a readable SQL file with a header: id, title, severity, required sources, response guidance |
| `allowlist.json` | Exceptions; the engine refuses an entry without an owner, a reason and an expiry, and ignores an entry after it expires |
| `capture/` | `workload.sh` (harmless analogs in a busybox container), `capture.sh` (host `strace`), `normalize_strace.py` |
| `scripts/` | `run-lab.sh` (everything), `summarize.py` (assertions and the scored table) |
| `tests/test_detections.py` | 23 tests: determinism, schema rejection, pinned confusion matrix, PID reuse, exception expiry, deduplication, blind coverage, clocks, label leakage, parser |
| `evidence/` | Sanitized output of the run below |

## Validation

Recorded run (`evidence/versions.txt`): Python 3.13.18, SQLite 3.53.1, Linux 6.18.44, strace 6.8, Docker 29.9.2.

```bash
python3 labs/linux-host-telemetry/tests/test_detections.py        # 23 tests, standard library only
bash labs/linux-host-telemetry/scripts/run-lab.sh                 # corpus + rules + (if available) real capture
```

| Check | Observed |
| --- | --- |
| Unit tests | 23 passed |
| Synthetic corpus | 855 events, 42 scenarios (17 malicious-pattern, 17 benign look-alike, 6 control, 2 evasion), 27 deduplicated alerts, **0 alerts on 400 background-noise iterations** |
| Scenario-level totals over nine rules | TP 19, FP 7, FN 2, TN 216 |
| Documented residual false positives | 7 look-alikes (S04, S13, S23, S33, S44, S54, S82) alert by design and are pinned in the tests |
| Documented misses | 2 (S14 per-user crontab, S34 outbound from system `bash`) stay silent and are pinned |
| Network sensor removed | LNX-004 reported `blind`, no alert, and **not scored** as a true negative |
| Real capture (strace, busybox container) | 176 trace lines → 28 events → alerts from exactly LNX-002, 005, 006, 007, 009; LNX-004 silent on a private-address connect from `/tmp`; LNX-003 `blind` (strace cannot supply `ExecStart`) |

Full per-rule table, residual-false-positive analysis and response actions: see the [article](../../linux-security/host-telemetry-detection-lab.md#findings-and-interpretation).

## What was not tested

- Any production sensor: auditd, eBPF, Falco, Tetragon, osquery. The schema is inspired by what they emit; none was run.
- Detection on real fleet data, real adversary tradecraft, or adversaries who know the rules. Evasion is represented by two hand-written cases.
- `strace` as a sensor: its overhead and blind spots were not measured; it is a capture convenience.
- Rules LNX-001, 003, 004 and 008 against real kernel data (the capture exercises 002, 005, 006, 007, 009 and one negative for 004).
- Time to detect and time to contain: the lab reports **synthetic** latency from synthetic clocks only.
- Response actions: they are written guidance, never executed.

## Production considerations

See the [article](../../linux-security/host-telemetry-detection-lab.md#production-considerations) for rollout, detection, operability,
false positives, blast radius and rollback. In short: ship rules to a few hosts in report-only mode, own every exception
(owner + expiry), page on nothing until the residual false-positive sources for your environment are known, and treat a blind rule as an
incident in the telemetry pipeline, not as a quiet host.

## References

- Linux man-pages, [proc(5)](https://github.com/mkerrisk/man-pages/blob/master/man5/proc.5): `/proc/[pid]/stat` field 22, `starttime`, the time the process started after system boot.
- strace project, [strace(1)](https://github.com/strace/strace/blob/master/doc/strace.1.in): trace-line format (name, arguments, return value, `errno` on failure, octal modes).
- Tool versions: each tool's own version output, in `evidence/versions.txt`.

## Related maintained investigations

- [Host Telemetry Detection Lab (article)](../../linux-security/host-telemetry-detection-lab.md)
- [Linux Host Analysis Without Invented Attack Paths](../../linux-security/evidence-driven-host-analysis.md)
- [Docker image and runtime hardening lab](../docker-security/README.md)
