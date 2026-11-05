#!/usr/bin/env python3
"""Tests for labs/linux-host-telemetry. Run: python3 labs/linux-host-telemetry/tests/test_detections.py

Standard library only. These are tests of DETECTION LOGIC against a synthetic,
labeled corpus. They do not measure how well the rules would perform on real
fleets: the corpus was written by the rule author, so precision/recall here is a
regression guard and a statement of documented behaviour, not a population estimate.
"""
import copy
import datetime as dt
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
LAB = HERE.parent
sys.path.insert(0, str(LAB))
sys.path.insert(0, str(LAB / "capture"))

import engine  # noqa: E402
import generator  # noqa: E402
from normalize_strace import normalize  # noqa: E402


def corpus(seed=20261105):
    builder = generator.build(seed)
    events = sorted(builder.events, key=lambda e: (e["ingest_ts"], e["ts"]))
    for index, event in enumerate(events, 1):
        event["id"] = index
    return events, builder.scenarios


EVENTS, SCENARIOS = corpus()
RULES = engine.load_rules()
ALLOW = engine.Allowlist()


def evaluate(events=None, allow=None, sources=None):
    alerts, coverage = engine.run(events or EVENTS, RULES, allow or ALLOW, sources)
    return alerts, coverage


# Pinned on purpose: a documented false positive or miss that changes (better OR worse)
# must be a conscious edit to this table and to the README, not a silent drift.
PINNED = {
    "LNX-001": dict(TP=4, FP=1, FN=0, TN=24),
    "LNX-002": dict(TP=2, FP=1, FN=1, TN=23),
    "LNX-003": dict(TP=1, FP=1, FN=0, TN=24),
    "LNX-004": dict(TP=2, FP=1, FN=1, TN=23),
    "LNX-005": dict(TP=3, FP=1, FN=0, TN=24),
    "LNX-006": dict(TP=3, FP=1, FN=0, TN=24),
    "LNX-007": dict(TP=1, FP=0, FN=0, TN=25),
    "LNX-008": dict(TP=2, FP=0, FN=0, TN=25),
    "LNX-009": dict(TP=1, FP=1, FN=0, TN=24),
}


class Corpus(unittest.TestCase):
    def test_generator_is_deterministic_and_seed_sensitive(self):
        a, _ = corpus()
        b, _ = corpus()
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))
        c, _ = corpus(seed=1)
        self.assertNotEqual(json.dumps(a, sort_keys=True), json.dumps(c, sort_keys=True))

    def test_every_generated_event_is_labeled_synthetic(self):
        self.assertTrue(all(e["synthetic"] is True and e["origin"] == "synthetic-generator" for e in EVENTS))

    def test_only_documentation_address_ranges_are_used(self):
        for e in EVENTS:
            if e["event"] == "net_connect":
                self.assertTrue(e["dest_ip"].startswith(("203.0.113.", "198.51.100.")), e["dest_ip"])

    def test_every_rule_has_a_positive_and_a_negative_scenario(self):
        for rule in RULES:
            rid = rule["id"]
            positives = [s for s in SCENARIOS if s["class"] == "malicious_pattern" and rid in s["expected_rules"]]
            negatives = [s for s in SCENARIOS if s["class"] in ("benign_lookalike", "control") and rid not in s["expected_rules"]]
            self.assertTrue(positives, f"{rid}: no true-positive scenario")
            self.assertGreaterEqual(len(negatives), 1, f"{rid}: no negative scenario")
            # PINNED covers the benign-lookalike and evasion cases per rule.
            self.assertIn(rid, PINNED)


class Validation(unittest.TestCase):
    def mutate(self, **changes):
        event = copy.deepcopy(next(e for e in EVENTS if e["event"] == "process_start"))
        for key, value in changes.items():
            if value is KeyError:
                event.pop(key)
            else:
                event[key] = value
        return event

    def test_malformed_events_are_rejected(self):
        cases = {
            "missing required field": self.mutate(host=KeyError),
            "unknown event type": self.mutate(event="kernel_panic"),
            "event from the wrong source": self.mutate(source="net"),
            "ingest before event": self.mutate(ingest_ts="2000-01-01T00:00:00.000Z"),
            "origin unknown": self.mutate(origin="production"),
            "flag contradicts origin": self.mutate(origin="strace-capture"),  # synthetic stays True
            "process_start without start time": self.mutate(pstart=None),
        }
        for label, event in cases.items():
            with self.subTest(label), self.assertRaises(engine.ValidationError):
                engine.validate(event, 1)

    def test_allowlist_entries_require_owner_reason_and_expiry(self):
        for missing in ("owner", "reason", "expires"):
            entry = {"rule": "LNX-005", "field": "exe", "pattern": "^/x$", "owner": "o", "reason": "r", "expires": "2030-01-01"}
            entry.pop(missing)
            with tempfile.NamedTemporaryFile("w", suffix=".json") as fh:
                json.dump({"entries": [entry]}, fh)
                fh.flush()
                with self.subTest(missing), self.assertRaises(engine.ValidationError):
                    engine.Allowlist(fh.name)

    def test_rules_cannot_read_labels_or_provenance(self):
        for rule in RULES:
            for forbidden in ("scenario", "synthetic", "origin"):
                self.assertNotIn(forbidden, rule["sql"].lower(), f"{rule['id']} references {forbidden}: label leakage")


class Detection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alerts, cls.coverage = evaluate()
        cls.table, cls.unexpected, cls.background = engine.score(cls.alerts, SCENARIOS, RULES, cls.coverage)

    def test_background_noise_produces_no_alerts(self):
        self.assertEqual(self.background, [])

    def test_every_outcome_matches_its_documented_expectation(self):
        self.assertEqual(self.unexpected, [])

    def test_confusion_matrix_is_pinned(self):
        for rid, expected in PINNED.items():
            got = {k: self.table[rid][k] for k in ("TP", "FP", "FN", "TN")}
            self.assertEqual(got, expected, rid)

    def test_known_residual_false_positives_and_misses_stay_visible(self):
        fp = {s["id"] for s in SCENARIOS if s["class"] == "benign_lookalike" and s["expected_rules"]}
        self.assertEqual(fp, {"S04", "S13", "S23", "S33", "S44", "S54", "S82"})
        evasions = {s["id"] for s in SCENARIOS if s["class"] == "evasion"}
        self.assertEqual(evasions, {"S14", "S34"})
        fired = {(a["scenario"], a["rule"]) for a in self.alerts}
        self.assertNotIn(("S14", "LNX-002"), fired)  # the miss is real
        self.assertNotIn(("S34", "LNX-004"), fired)

    def test_pid_reuse_is_resolved_by_identity_not_pid(self):
        s06 = [a for a in self.alerts if "S06" in a["scenarios"]]
        self.assertEqual(s06, [], "identity-aware ancestry must not blame the reused pid's former parent")
        # The same rule with the start-time condition removed (a pid-only join) DOES alert on S06.
        rule = next(r for r in RULES if r["id"] == "LNX-001")
        naive_sql = rule["sql"].replace("AND p.pid = a.ppid AND p.pstart = a.ppstart", "AND p.pid = a.ppid")
        self.assertNotEqual(naive_sql, rule["sql"], "test is stale: the identity join text changed")
        naive_rule = dict(rule, sql=naive_sql)
        naive_alerts, _ = engine.run(EVENTS, [naive_rule], ALLOW)
        # S06's hit is folded into the earlier "nginx > sh" alert by deduplication, so look at the folded set.
        self.assertTrue([a for a in naive_alerts if "S06" in a["scenarios"]], "a pid-only join should misattribute S06")

    def test_deduplication_collapses_repeats_but_not_distant_events(self):
        s90 = [a for a in self.alerts if a["scenario"] == "S90"]
        self.assertEqual(len(s90), 1)
        self.assertEqual(s90[0]["count"], 50)
        # Two identical hits more than the window apart are two alerts.
        base = next(e for e in EVENTS if e["scenario"] == "S10" and e["event"] == "file_write")
        later = dict(base, id=base["id"] + 100000, ts="2026-11-05T11:00:00.000Z", ingest_ts="2026-11-05T11:00:01.000Z")
        alerts, _ = engine.run([base, later], RULES, ALLOW)
        self.assertEqual(len([a for a in alerts if a["rule"] == "LNX-002"]), 2)

    def test_allowlist_exceptions_expire(self):
        s43 = [a for a in self.alerts if a["scenario"] == "S43"]
        s45 = [a for a in self.alerts if a["scenario"] == "S45"]
        self.assertEqual(s43, [], "valid exception suppresses")
        self.assertEqual(len(s45), 1, "expired exception no longer suppresses")
        # Moving the clock back inside the exception's life suppresses S45 as well.
        shifted = []
        for e in EVENTS:
            if e["scenario"] == "S45":
                e = dict(e, ts="2026-05-01" + e["ts"][10:], ingest_ts="2026-05-01" + e["ingest_ts"][10:])
            shifted.append(e)
        alerts, _ = engine.run(shifted, RULES, ALLOW)
        self.assertEqual([a for a in alerts if a["scenario"] == "S45"], [])

    def test_missing_source_makes_a_rule_blind_not_clean(self):
        alerts, coverage = evaluate(sources={"exec", "file"})
        self.assertEqual(coverage["LNX-004"]["status"], "blind")
        self.assertEqual(coverage["LNX-004"]["missing_sources"], ["net"])
        self.assertEqual([a for a in alerts if a["rule"] == "LNX-004"], [])
        table, _, _ = engine.score(alerts, SCENARIOS, RULES, coverage)
        self.assertTrue(table["LNX-004"]["blind"])
        self.assertEqual(sum(table["LNX-004"][k] for k in ("TP", "FP", "FN", "TN")), 0, "a blind rule must not be scored as TN")

    def test_missing_field_makes_a_rule_blind(self):
        stripped = [{k: v for k, v in e.items() if k != "exec_start"} for e in EVENTS]
        _, coverage = evaluate(stripped)
        self.assertEqual(coverage["LNX-003"]["status"], "blind")
        self.assertEqual(coverage["LNX-003"]["missing_fields"], ["exec_start"])

    def test_clocks_ingestion_lag_dominates_synthetic_latency(self):
        by = {a["scenario"]: a for a in self.alerts if a["rule"] in ("LNX-001", "LNX-006") and a["scenario"] in ("S01", "S91")}
        self.assertLess(by["S01"]["synthetic_latency_seconds"], 15)
        self.assertGreaterEqual(by["S91"]["synthetic_latency_seconds"], 125)
        for a in self.alerts:
            self.assertGreaterEqual(a["synthetic_latency_seconds"], 0)


class StraceNormalizer(unittest.TestCase):
    # HANDWRITTEN parser fixture in strace's format (not a recording). The recorded
    # capture is produced by capture/capture.sh and evaluated by scripts/run-lab.sh.
    LINES = """\
100 1000.000001 execve("/bin/sh", ["sh", "-c", "x"], 0x1 /* 3 vars */) = 0
100 1000.000010 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD, child_tidptr=0x7f) = 101
101 1000.000020 execve("/bin/cat", ["cat", "/etc/shadow"], 0x1 /* 3 vars */) = 0
101 1000.000030 openat(AT_FDCWD, "/etc/shadow", O_RDONLY) = 3
101 1000.000031 openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
101 1000.000032 openat(AT_FDCWD, "/etc/nope", O_RDONLY) = -1 ENOENT (No such file or directory)
100 1000.000040 openat(AT_FDCWD, "/etc/cron.d/x", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 4
100 1000.000050 chmod("/tmp/x", 04755) = 0
100 1000.000060 connect(3, {sa_family=AF_INET, sin_port=htons(9000), sin_addr=inet_addr("172.17.0.2")}, 16) = 0
100 1000.000061 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("198.51.100.7")}, 16) = 0
100 1000.000062 connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("10.0.0.1")}, 16) = -1 ECONNREFUSED (Connection refused)
100 1000.000070 +++ exited with 0 +++
""".splitlines()

    @classmethod
    def setUpClass(cls):
        cls.events = normalize(cls.LINES, "/bin/busybox")

    def kinds(self):
        return [(e["event"], e.get("path") or e.get("dest_ip") or e["exe"]) for e in self.events]

    def test_expected_events_only(self):
        self.assertEqual(self.kinds(), [
            ("process_start", "/bin/sh"), ("process_start", "/bin/cat"), ("file_read", "/etc/shadow"),
            ("file_write", "/etc/cron.d/x"), ("file_truncate", "/etc/cron.d/x"), ("file_chmod", "/tmp/x"),
            ("net_connect", "172.17.0.2"), ("net_connect", "198.51.100.7"),
        ])

    def test_failed_syscalls_and_library_reads_are_dropped(self):
        paths = [e.get("path") for e in self.events]
        self.assertNotIn("/etc/nope", paths)
        self.assertFalse([p for p in paths if p and p.startswith("/lib/")])

    def test_process_identity_and_ancestry(self):
        cat_exec = next(e for e in self.events if e["exe"] == "/bin/cat" and e["event"] == "process_start")
        sh_exec = next(e for e in self.events if e["exe"] == "/bin/sh" and e["event"] == "process_start")
        self.assertEqual((cat_exec["ppid"], cat_exec["ppstart"]), (sh_exec["pid"], sh_exec["pstart"]))
        self.assertNotEqual(cat_exec["pstart"], sh_exec["pstart"])

    def test_modes_and_destinations(self):
        chmod = next(e for e in self.events if e["event"] == "file_chmod")
        self.assertEqual(chmod["mode"], 0o4755)
        classes = [e["dest_class"] for e in self.events if e["event"] == "net_connect"]
        self.assertEqual(classes, ["private", "public"])

    def test_normalized_events_pass_engine_validation_and_are_not_synthetic(self):
        for e in self.events:
            engine.validate(e, 0)
            self.assertFalse(e["synthetic"])
            self.assertEqual(e["origin"], "strace-capture")


class CommandLine(unittest.TestCase):
    def test_generator_cli_writes_the_same_bytes_twice(self):
        with tempfile.TemporaryDirectory() as tmp:
            outs = []
            for run in ("a", "b"):
                path = pathlib.Path(tmp) / f"{run}.jsonl"
                subprocess.run([sys.executable, str(LAB / "generator.py"), "--out", str(path), "--scenarios", str(pathlib.Path(tmp) / f"{run}.json")],
                               check=True, capture_output=True)
                outs.append(path.read_bytes())
            self.assertEqual(outs[0], outs[1])


if __name__ == "__main__":
    unittest.main(verbosity=2)
