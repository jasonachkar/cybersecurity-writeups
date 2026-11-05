#!/usr/bin/env python3
"""Normalize `strace -f -ttt -qq` output into the engine's event schema.

These events are REAL kernel-observed syscalls from a throwaway container
(origin "strace-capture", synthetic=false) - benign analogs of the behaviours the
rules look for. strace is a capture convenience for this lab, not a production
sensor: it perturbs timing, sees only the syscalls it is asked to trace, and
cannot supply fields such as a unit file's parsed ExecStart.

Process identity: strace gives host PIDs but no start times, so pstart is a
per-trace ordinal (order of first appearance). That preserves "same pid, different
process" distinctions inside one capture; it is not a kernel start time.

Usage: normalize_strace.py <strace.txt> <root-exe> <out.jsonl>
"""
import datetime as dt
import ipaddress
import json
import re
import sys

LINE = re.compile(r"^(\d+)\s+(\d+\.\d+)\s+(.*)$")
CALL = re.compile(r"^(\w+)\((.*)\)\s+=\s+(-?\d+|\?)(?:\s.*)?$")
RESUMED = re.compile(r"^<\.\.\. (\w+) resumed>(.*)\)\s+=\s+(-?\d+|\?)(?:\s.*)?$")
QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')
SKIP_READ_PREFIXES = ("/lib/", "/usr/lib/", "/lib64/", "/proc/", "/sys/", "/dev/", "/etc/ld.so", "/etc/localtime")


INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7", "fe80::/10")]


def classify(ip):
    """loopback / private (RFC 1918, link-local, ULA) / public (everything else).

    Deliberately not ipaddress.is_private: that is True for the RFC 5737 documentation
    ranges this lab uses as stand-ins for "somewhere on the Internet".
    """
    address = ipaddress.ip_address(ip)
    if address.is_loopback:
        return "loopback"
    return "private" if any(address in network for network in INTERNAL) else "public"


def iso(epoch):
    return dt.datetime.fromtimestamp(float(epoch), dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def normalize(lines, root_exe, host="lab-capture-container", boot="capture-boot"):
    procs, events, ordinal = {}, [], [0]

    def new_proc(pid, ppid, exe, cmdline):
        ordinal[0] += 1
        parent = procs.get(ppid)
        procs[pid] = {"pid": pid, "pstart": ordinal[0], "ppid": ppid, "ppstart": parent["pstart"] if parent else 0, "exe": exe, "cmdline": cmdline}
        return procs[pid]

    def emit(ts, kind, source, proc, **extra):
        event = {"id": len(events) + 1, "ts": iso(ts), "ingest_ts": iso(ts), "host": host, "boot_id": boot, "source": source,
                 "event": kind, "pid": proc["pid"], "pstart": proc["pstart"], "ppid": proc["ppid"], "ppstart": proc["ppstart"],
                 "uid": 0, "exe": proc["exe"], "cmdline": proc["cmdline"], "tty": None, "scenario": "capture",
                 "synthetic": False, "origin": "strace-capture"}
        event.update(extra)
        events.append(event)

    for raw in lines:
        m = LINE.match(raw.rstrip("\n"))
        if not m:
            continue
        pid, ts, rest = int(m.group(1)), m.group(2), m.group(3)
        if rest.startswith("+++") or rest.startswith("---"):
            continue
        name = args = ret = None
        c = CALL.match(rest)
        if c:
            name, args, ret = c.group(1), c.group(2), c.group(3)
        else:
            r = RESUMED.match(rest)
            if r:
                name, args, ret = r.group(1), r.group(2), r.group(3)
        if name is None or ret in (None, "?"):
            continue
        ret = int(ret)
        if pid not in procs:
            # The first traced process was already running when the tracer attached.
            new_proc(pid, 0, root_exe, root_exe)
        proc = procs[pid]
        if name in ("clone", "fork", "vfork", "clone3"):
            if ret > 0:
                new_proc(ret, pid, proc["exe"], proc["cmdline"])
            continue
        if ret < 0:
            continue  # failed syscalls are not behaviour
        quoted = QUOTED.findall(args)
        if name == "execve" and quoted:
            argv = QUOTED.findall(args.split("], ")[0]) if "[" in args else quoted
            proc["exe"], proc["cmdline"] = quoted[0], " ".join(argv[1:]) if len(argv) > 1 else quoted[0]
            emit(ts, "process_start", "exec", proc)
        elif name in ("open", "openat") and quoted:
            path, flags = quoted[0], args
            writes = any(f in flags for f in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"))
            if writes:
                emit(ts, "file_write", "file", proc, path=path)
                if "O_TRUNC" in flags:
                    emit(ts, "file_truncate", "file", proc, path=path)
            elif not path.startswith(SKIP_READ_PREFIXES):
                emit(ts, "file_read", "file", proc, path=path)
        elif name in ("chmod", "fchmodat") and quoted:
            mode = re.search(r",\s*(0[0-7]+)\s*(?:\)|,|$)", args)
            if mode:
                emit(ts, "file_chmod", "file", proc, path=quoted[0], mode=int(mode.group(1), 8), is_dir=False)
        elif name == "truncate" and quoted:
            emit(ts, "file_truncate", "file", proc, path=quoted[0])
        elif name in ("unlink", "unlinkat") and quoted:
            emit(ts, "file_delete", "file", proc, path=quoted[0])
        elif name == "connect":
            ip = re.search(r'inet_addr\("([^"]+)"\)', args)
            port = re.search(r"sin_port=htons\((\d+)\)", args)
            if ip and port:
                emit(ts, "net_connect", "net", proc, dest_ip=ip.group(1), dest_port=int(port.group(1)), dest_class=classify(ip.group(1)))
    return events


if __name__ == "__main__":
    trace, root_exe, out = sys.argv[1:4]
    with open(trace) as fh:
        events = normalize(fh, root_exe)
    with open(out, "w") as fh:
        for e in events:
            fh.write(json.dumps(e, sort_keys=True) + "\n")
    print(f"{len(events)} events", file=sys.stderr)
