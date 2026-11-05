#!/usr/bin/env python3
"""Detection engine for labs/linux-host-telemetry: events in, deduplicated alerts out.

Rules are plain SQL files in rules/ run against an in-memory SQLite table, so every
detection is a readable query with no hidden logic. The engine adds only what SQL
should not carry: schema validation, allowlist evaluation (owner + expiry), source
coverage ("blind" instead of "clean"), batching clocks, and deduplication.

Usage: engine.py --events events.jsonl [--scenarios scenarios.json] [--sources exec,file,net]
"""
import argparse
import datetime as dt
import json
import os
import pathlib
import re
import sqlite3
import sys

HERE = pathlib.Path(__file__).resolve().parent
EVENT_TYPES = {"process_start": "exec", "file_read": "file", "file_write": "file", "file_chmod": "file",
               "file_truncate": "file", "file_delete": "file", "net_connect": "net"}
REQUIRED = ["id", "ts", "ingest_ts", "host", "boot_id", "source", "event", "synthetic", "origin"]
ORIGINS = {"synthetic-generator": True, "strace-capture": False}  # origin -> value of the synthetic flag
COLUMNS = ["id", "ts", "ingest_ts", "host", "boot_id", "source", "event", "pid", "pstart", "ppid", "ppstart", "uid",
           "exe", "cmdline", "tty", "path", "mode", "dest_ip", "dest_port", "dest_class", "exec_start", "is_dir", "scenario", "synthetic", "origin"]
BATCH_SECONDS = 5          # the engine evaluates in 5 s micro-batches (synthetic clock)
DEDUP_WINDOW_SECONDS = 300 # identical (rule, host, subject) alerts within 5 min collapse into one


class ValidationError(ValueError):
    pass


def parse_ts(value):
    return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=dt.timezone.utc)


def validate(event, line_no):
    for field in REQUIRED:
        if field not in event:
            raise ValidationError(f"line {line_no}: missing required field {field!r}")
    if event["event"] not in EVENT_TYPES:
        raise ValidationError(f"line {line_no}: unknown event type {event['event']!r}")
    if EVENT_TYPES[event["event"]] != event["source"]:
        raise ValidationError(f"line {line_no}: event {event['event']!r} cannot come from source {event['source']!r}")
    if event["origin"] not in ORIGINS:
        raise ValidationError(f"line {line_no}: unknown origin {event['origin']!r}")
    if event["synthetic"] is not ORIGINS[event["origin"]]:
        raise ValidationError(f"line {line_no}: synthetic={event['synthetic']!r} contradicts origin {event['origin']!r}")
    for field in ("ts", "ingest_ts"):
        parse_ts(event[field])
    if parse_ts(event["ingest_ts"]) < parse_ts(event["ts"]):
        raise ValidationError(f"line {line_no}: ingest_ts precedes ts")
    if event["event"] == "process_start":
        for field in ("pid", "pstart", "ppid", "ppstart", "exe"):
            if event.get(field) is None:
                raise ValidationError(f"line {line_no}: process_start without {field}")


def load_events(path):
    events = []
    with open(path) as fh:
        for line_no, line in enumerate(fh, 1):
            if not line.strip():
                continue
            event = json.loads(line)
            validate(event, line_no)
            events.append(event)
    return events


class Allowlist:
    def __init__(self, path=HERE / "allowlist.json"):
        self.entries = json.loads(pathlib.Path(path).read_text())["entries"] if path else []
        for entry in self.entries:
            for key in ("rule", "pattern", "owner", "reason", "expires"):
                if not entry.get(key):
                    raise ValidationError(f"allowlist entry {entry} lacks {key}: exceptions need an owner, a reason and an expiry")
            re.compile(entry["pattern"])

    def allowed(self, rule, ts, exe, cmdline, path, parent_exe):
        day = ts[:10]
        for entry in self.entries:
            if entry["rule"] != rule or day > entry["expires"]:
                continue
            value = {"exe": exe, "cmdline": cmdline, "path": path}.get(entry.get("field", "exe"), "") or ""
            if not re.search(entry["pattern"], value):
                continue
            if entry.get("parent_exe") and entry["parent_exe"] != (parent_exe or ""):
                continue
            if entry.get("cmdline_pattern") and not re.search(entry["cmdline_pattern"], cmdline or ""):
                continue
            return True
        return False


def parse_rule(path):
    text = path.read_text()
    meta = dict(re.findall(r"^-- (\w+): (.*)$", text, re.M))
    for key in ("id", "title", "severity", "requires", "response"):
        if key not in meta:
            raise ValidationError(f"{path.name}: missing '-- {key}:' header")
    meta["requires"] = {s.strip() for s in meta["requires"].split(",")}
    # Optional: event fields the rule cannot work without (a source can be present but lack a field).
    meta["requires_fields"] = {s.strip() for s in meta.get("requires_fields", "").split(",") if s.strip()}
    meta["sql"] = text
    return meta


def load_rules(rules_dir=HERE / "rules"):
    return sorted((parse_rule(p) for p in pathlib.Path(rules_dir).glob("*.sql")), key=lambda r: r["id"])


def connect(events, allowlist):
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.create_function("basename", 1, lambda p: (p or "").rsplit("/", 1)[-1].split(" (deleted)")[0])
    db.create_function("regexp", 2, lambda pattern, value: 1 if value is not None and re.search(pattern, value) else 0)
    db.create_function("is_allowed", 6, lambda rule, ts, exe, cmd, path, parent: 1 if allowlist.allowed(rule, ts, exe, cmd, path, parent) else 0)
    db.execute(f"CREATE TABLE events ({', '.join(c + (' INTEGER PRIMARY KEY' if c == 'id' else '') for c in COLUMNS)})")
    db.execute("CREATE INDEX proc_identity ON events (host, boot_id, pid, pstart)")
    rows = [[(1 if e.get(c) is True else 0 if e.get(c) is False else e.get(c)) for c in COLUMNS] for e in events]
    db.executemany(f"INSERT INTO events VALUES ({','.join('?' * len(COLUMNS))})", rows)
    return db


def run(events, rules, allowlist, sources=None):
    """Return (alerts, coverage). sources=None means: whatever the events contain."""
    available = set(sources) if sources is not None else {e["source"] for e in events}
    usable = [e for e in events if e["source"] in available]
    db = connect(usable, allowlist)
    by_id = {e["id"]: e for e in usable}
    coverage, hits = {}, []
    for rule in rules:
        missing = sorted(rule["requires"] - available)
        missing_fields = sorted(f for f in rule["requires_fields"] if not any(e.get(f) is not None for e in usable))
        if missing or missing_fields:
            coverage[rule["id"]] = {"status": "blind", "missing_sources": missing, "missing_fields": missing_fields}
            continue
        coverage[rule["id"]] = {"status": "evaluated", "missing_sources": [], "missing_fields": []}
        for row in db.execute(rule["sql"]):
            hits.append({"rule": rule["id"], "severity": rule["severity"], "event_id": row["event_id"], "host": row["host"],
                         "subject": row["subject"], "detail": row["detail"]})
    # Deduplicate: same (rule, host, subject) within the window collapses into one alert with a count.
    hits.sort(key=lambda h: by_id[h["event_id"]]["ingest_ts"])
    alerts, open_alert = [], {}
    for hit in hits:
        event = by_id[hit["event_id"]]
        key = (hit["rule"], hit["host"], hit["subject"])
        ingest = parse_ts(event["ingest_ts"])
        current = open_alert.get(key)
        if current and (ingest - current["_last"]).total_seconds() <= DEDUP_WINDOW_SECONDS:
            current["count"] += 1
            current["_last"] = ingest
            current["event_ids"].append(hit["event_id"])
            # Evaluation-only: which labeled scenarios were folded into this alert. A real
            # pipeline has no such field - the folded activity is visible only as the count.
            current["_scenarios"].add(event.get("scenario"))
            continue
        batch_end = dt.datetime.fromtimestamp(((ingest.timestamp() // BATCH_SECONDS) + 1) * BATCH_SECONDS, dt.timezone.utc)
        alert = dict(hit, scenario=event.get("scenario"), count=1, event_ids=[hit["event_id"]], _last=ingest,
                     _scenarios={event.get("scenario")},
                     event_ts=event["ts"], ingest_ts=event["ingest_ts"],
                     alert_ts=batch_end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                     synthetic_latency_seconds=round((batch_end - parse_ts(event["ts"])).total_seconds(), 1))
        open_alert[key] = alert
        alerts.append(alert)
    for alert in alerts:
        alert.pop("_last")
        alert["scenarios"] = sorted(alert.pop("_scenarios"))
    return alerts, coverage


def score(alerts, scenarios, rules, coverage):
    """Scenario-level confusion matrix per rule; background noise is counted separately.

    Class semantics (see generator.py):
      malicious_pattern   rule in expected_rules -> TP if it fired else FN
      evasion             rule in evades         -> FN if it stayed silent else TP (the known miss closed)
      benign_lookalike    any rule               -> FP if it fired else TN (expected_rules lists KNOWN residual FPs)
      control             any rule               -> FP if it fired else TN
    A rule firing on a malicious scenario it is not responsible for is "incidental" (neither TP nor FP).
    unexpected_outcomes compares the actual result with the DOCUMENTED one, so a documented false
    positive or miss that silently changes (better or worse) is surfaced.
    """
    fired = {}
    for alert in alerts:
        for scenario in alert["scenarios"]:  # includes scenarios folded in by deduplication
            fired.setdefault(scenario, set()).add(alert["rule"])
    table = {r["id"]: {"TP": 0, "FP": 0, "FN": 0, "TN": 0, "incidental": 0, "blind": coverage[r["id"]]["status"] == "blind"} for r in rules}
    unexpected = []
    for sc in scenarios:
        for rule in rules:
            rid = rule["id"]
            if table[rid]["blind"]:
                continue
            did = rid in fired.get(sc["id"], set())
            documented = rid in sc["expected_rules"]
            if sc["class"] == "malicious_pattern":
                if documented:
                    table[rid]["TP" if did else "FN"] += 1
                elif did:
                    table[rid]["incidental"] += 1
            elif sc["class"] == "evasion":
                if rid in sc.get("evades", []):
                    table[rid]["TP" if did else "FN"] += 1
                elif did:
                    table[rid]["FP"] += 1
                else:
                    table[rid]["TN"] += 1
            else:  # benign_lookalike, control
                table[rid]["FP" if did else "TN"] += 1
            if sc["class"] == "evasion" and rid in sc.get("evades", []):
                documented = False
            if did != documented and not (sc["class"] == "malicious_pattern" and not documented):
                unexpected.append({"scenario": sc["id"], "rule": rid, "documented_to_fire": documented, "fired": did, "class": sc["class"]})
    background = [a for a in alerts if "bg" in a["scenarios"]]
    return table, unexpected, background


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", required=True)
    ap.add_argument("--scenarios")
    ap.add_argument("--sources", help="comma-separated telemetry sources actually collected (default: those present)")
    ap.add_argument("--allowlist", default=str(HERE / "allowlist.json"))
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    events = load_events(args.events)
    rules = load_rules()
    sources = set(args.sources.split(",")) if args.sources else None
    alerts, coverage = run(events, rules, Allowlist(args.allowlist), sources)
    out = {"events": len(events), "alerts": alerts, "coverage": coverage}
    if args.scenarios:
        scen = json.loads(pathlib.Path(args.scenarios).read_text())["scenarios"]
        table, outcomes, background = score(alerts, scen, rules, coverage)
        out.update(confusion=table, unexpected_outcomes=outcomes, background_alerts=len(background))
    print(json.dumps(out, indent=2, sort_keys=True) if args.json else f"{len(events)} events -> {len(alerts)} alerts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
