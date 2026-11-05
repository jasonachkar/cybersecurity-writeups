#!/usr/bin/env python3
"""Inventory an image filesystem read from `docker export` on stdin.

Attack surface is not a CVE count. This reports what an attacker who gets code
execution inside the container could reach: shells, package managers, compilers,
setuid/setgid files, world-writable files and executable count.
Usage: docker export <container> | inventory.py
"""
import json
import sys
import tarfile

SHELLS = {"bin/sh", "bin/bash", "bin/ash", "usr/bin/sh", "usr/bin/bash", "bin/dash"}
PACKAGE_MANAGERS = {"sbin/apk", "usr/bin/apt", "usr/bin/apt-get", "usr/bin/dpkg", "usr/bin/yum", "usr/bin/dnf", "usr/bin/pip", "usr/local/bin/pip"}
COMPILERS = {"usr/local/go/bin/go", "usr/bin/gcc", "usr/bin/cc", "usr/bin/python3", "usr/local/bin/node"}

report = {"files": 0, "symlinks": 0, "executables": 0, "setuid_or_setgid": [], "world_writable_files": 0,
          "shells": [], "package_managers": [], "compilers_or_interpreters": [], "size_bytes": 0}
with tarfile.open(fileobj=sys.stdin.buffer, mode="r|") as archive:
    for member in archive:
        name = member.name.lstrip("./")
        if member.issym() or member.islnk():
            report["symlinks"] += 1
            # A symlink to busybox is still a usable shell or package manager.
            if name in SHELLS:
                report["shells"].append(name)
            if name in PACKAGE_MANAGERS:
                report["package_managers"].append(name)
            continue
        if not member.isfile():
            continue
        report["files"] += 1
        report["size_bytes"] += member.size
        if member.mode & 0o111:
            report["executables"] += 1
        if member.mode & 0o6000:
            report["setuid_or_setgid"].append(name)
        if member.mode & 0o002:
            report["world_writable_files"] += 1
        if name in SHELLS:
            report["shells"].append(name)
        if name in PACKAGE_MANAGERS:
            report["package_managers"].append(name)
        if name in COMPILERS:
            report["compilers_or_interpreters"].append(name)
for key in ("setuid_or_setgid", "shells", "package_managers", "compilers_or_interpreters"):
    report[key] = sorted(set(report[key]))
print(json.dumps(report, indent=2, sort_keys=True))
