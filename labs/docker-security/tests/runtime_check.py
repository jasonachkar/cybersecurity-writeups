#!/usr/bin/env python3
"""Assert the OBSERVED runtime results of the Docker lab. Usage: runtime_check.py <outdir>

Reads the JSON that scripts/run-lab.sh wrote and fails (exit 1) when any claimed
control is not what the running container actually reported. Supply-chain
assertions run only when those steps executed; otherwise they print SKIP with the
recorded reason - a skip is never reported as a pass.
"""
import json
import pathlib
import sys

out = pathlib.Path(sys.argv[1])
failures = []
passes = 0


def load(rel):
    path = out / rel
    return json.loads(path.read_text()) if path.exists() else None


def check(name, condition, detail=""):
    global passes
    if condition:
        passes += 1
        print(f"PASS  {name}")
    else:
        failures.append(name)
        print(f"FAIL  {name}  {detail}")


def probes(report):
    return {p["name"].split(" ")[0]: p for p in report["probes"]}


def read_exit(rel):
    path = out / rel
    return int(path.read_text().strip()) if path.exists() else None


# ---- insecure baseline: every dangerous capability is observable --------------
ins = load("runtime/insecure-probe.json")
check("insecure: probe output exists", ins is not None)
if ins:
    p, pr = ins["posture"], probes(ins)
    check("insecure: runs as uid 0", p["uid"] == 0, p["uid"])
    check("insecure: large effective capability set (privileged)", len(p["cap_eff"]) >= 30, len(p["cap_eff"]))
    check("insecure: SYS_ADMIN present", "SYS_ADMIN" in p["cap_eff"])
    check("insecure: no_new_privs off", p["no_new_privs"] == "0", p["no_new_privs"])
    check("insecure: seccomp off", p["seccomp_mode"] == "0", p["seccomp_mode"])
    check("insecure: root filesystem writable", p["root_fs_mounted_read_only"] is False)
    check("insecure: no memory limit", "9223372036854771712" in p["memory_limit"] or p["memory_limit"].startswith("max"), p["memory_limit"])
    check("insecure: no pids limit", p["pids_limit"].startswith("max"), p["pids_limit"])
    check("insecure: host PID namespace visible", p["pid1_comm"] != "posture" and p["visible_process_count"] > 10, (p["pid1_comm"], p["visible_process_count"]))
    for name in ("write_root_filesystem", "write_tmp_scratch", "chown_to_other_uid", "mknod_char_device",
                 "raw_socket", "mount_tmpfs", "clone_new_user_namespace", "docker_socket_reachable",
                 "host_canary_read", "host_canary_write", "tcp_connect_canary"):
        check(f"insecure: {name} allowed", pr.get(name, {}).get("allowed") is True, pr.get(name))
    check("insecure: docker API answered /_ping", "200 OK" in pr.get("docker_socket_reachable", {}).get("detail", ""))
    fork = load("runtime/insecure-forktest.json")
    check("insecure: all 200 children started (no PID limit)", bool(fork) and fork["started"] == fork["requested"], fork)
    check("insecure: 512 MiB allocation succeeds (no memory limit)", read_exit("runtime/insecure-memtest.exit") == 0)
    owner = (out / "runtime/insecure-host-canary-owner.txt")
    check("insecure: file written into the bind-mounted host directory is owned by uid 0",
          owner.exists() and owner.read_text().split()[0] == "0", owner.read_text() if owner.exists() else None)

# ---- hardened: the same probes are refused -------------------------------------
har = load("runtime/hardened-probe.json")
check("hardened: probe output exists", har is not None)
if har:
    p, pr = har["posture"], probes(har)
    check("hardened: runs as uid 65532", p["uid"] == 65532, p["uid"])
    check("hardened: effective capability set is empty", p["cap_eff"] == [], p["cap_eff"])
    check("hardened: no_new_privs on", p["no_new_privs"] == "1", p["no_new_privs"])
    check("hardened: seccomp filter active", p["seccomp_mode"] == "2" and p["seccomp_filters"] == "1", (p["seccomp_mode"], p["seccomp_filters"]))
    check("hardened: root filesystem read-only", p["root_fs_mounted_read_only"] is True)
    check("hardened: memory limit 128 MiB", p["memory_limit"].startswith("134217728"), p["memory_limit"])
    check("hardened: pids limit 64", p["pids_limit"].startswith("64"), p["pids_limit"])
    check("hardened: cpu quota 0.5 CPU", p["cpu_quota"].startswith("50000"), p["cpu_quota"])
    check("hardened: own PID namespace (app is PID 1, few processes)", p["pid1_comm"] == "posture" and p["visible_process_count"] < 10, (p["pid1_comm"], p["visible_process_count"]))
    expect_denied = {
        "write_root_filesystem": "EROFS", "chown_to_other_uid": "EPERM", "mknod_char_device": "EPERM",
        "raw_socket": "EPERM", "mount_tmpfs": "EPERM", "clone_new_user_namespace": "EPERM",
        "docker_socket_present": "ENOENT", "host_canary_mounted": "ENOENT",
    }
    for name, errno in expect_denied.items():
        got = pr.get(name, {})
        check(f"hardened: {name} denied with {errno}", got.get("allowed") is False and got.get("errno") == errno, got)
    check("hardened: scratch tmpfs still writable (the app is not broken)", pr["write_tmp_scratch"]["allowed"] is True)
    canary = pr.get("tcp_connect_canary", {})
    check("hardened: canary unreachable and name not resolvable (network topology)", canary.get("allowed") is False and "name resolution failed" in canary.get("detail", ""), canary)
    health = out / "runtime/hardened-health-before.txt"
    check("hardened: container reported healthy via image HEALTHCHECK", health.exists() and health.read_text().strip() == "healthy")
    fork = load("runtime/hardened-forktest.json")
    check("hardened: PID limit stops child creation with EAGAIN", bool(fork) and fork["started"] < fork["requested"] and fork["first_error"] == "EAGAIN", fork)
    mem = read_exit("runtime/hardened-memtest.exit")
    check("hardened: 512 MiB allocation is OOM-killed under a 128 MiB limit (exit 137)", mem == 137, mem)

# ---- seccomp attribution controls (same hardening, different seccomp setting) ---
for label, mode, clone_allowed in (("unconfined", "0", True), ("default", "2", False), ("custom", "2", False)):
    ctl = load(f"runtime/hardened-seccomp-{label}-probe.json")
    check(f"control seccomp={label}: probe output exists", ctl is not None)
    if ctl:
        clone = probes(ctl)["clone_new_user_namespace"]
        check(f"control seccomp={label}: seccomp_mode {mode}", ctl["posture"]["seccomp_mode"] == mode, ctl["posture"]["seccomp_mode"])
        check(f"control seccomp={label}: user-namespace clone {'allowed' if clone_allowed else 'denied'}",
              clone["allowed"] is clone_allowed, clone)
        check(f"control seccomp={label}: capabilities still empty (so the denial is not a capability effect)", ctl["posture"]["cap_eff"] == [])

# ---- attack surface of the image filesystems ---------------------------------------
inv_i, inv_h = load("runtime/insecure-inventory.json"), load("runtime/hardened-inventory.json")
check("inventory: both images inventoried", inv_i is not None and inv_h is not None)
if inv_i and inv_h:
    check("inventory: insecure image ships a shell", bool(inv_i["shells"]), inv_i["shells"])
    check("inventory: insecure image ships a package manager", bool(inv_i["package_managers"]), inv_i["package_managers"])
    check("inventory: insecure image ships a compiler/toolchain", "usr/local/go/bin/go" in inv_i["compilers_or_interpreters"], inv_i["compilers_or_interpreters"])
    check("inventory: hardened image ships no shell", inv_h["shells"] == [], inv_h["shells"])
    check("inventory: hardened image ships no package manager", inv_h["package_managers"] == [], inv_h["package_managers"])
    check("inventory: hardened image ships no compiler or interpreter", inv_h["compilers_or_interpreters"] == [], inv_h["compilers_or_interpreters"])
    check("inventory: hardened image has no setuid/setgid files", inv_h["setuid_or_setgid"] == [], inv_h["setuid_or_setgid"])
    check("inventory: hardened image has far fewer executable files", inv_h["executables"] * 5 < inv_i["executables"], (inv_h["executables"], inv_i["executables"]))
    print(f"INFO  inventory: executables insecure={inv_i['executables']} hardened={inv_h['executables']}; "
          f"size insecure={inv_i['size_bytes']} hardened={inv_h['size_bytes']} bytes (file content)")

# ---- supply chain (only when executed) -----------------------------------------
scan = load("scan/summary.json")
if scan and scan.get("trivy", {}).get("version"):
    imgs = scan["images"]
    ins_n = imgs["insecure"]["unique_cve_package_pairs"]
    har_n = imgs["hardened"]["unique_cve_package_pairs"]
    # Deliberately NOT asserting hardened < insecure: CVE counts do not rank
    # attack surface (the observed result is the opposite - see README).
    print(f"INFO  scan: unique CVE/package findings insecure={ins_n} hardened={har_n} "
          "(a count of known CVEs is not an attack-surface measure)")
    for variant in ("insecure", "hardened"):
        entry = imgs[variant]
        check(f"scan: {variant} summary is internally consistent",
              entry["raw_findings"] >= entry["unique_cve_package_pairs"] and sum(entry["unique_by_severity"].values()) == entry["unique_cve_package_pairs"], entry)
    check("scan: SBOM-only scan agrees with the image scan for both variants",
          all(scan["sbom"][v]["unique_findings_from_sbom_only"] == imgs[v]["unique_cve_package_pairs"] for v in ("insecure", "hardened") if v in scan["sbom"]),
          {v: (scan["sbom"][v]["unique_findings_from_sbom_only"], imgs[v]["unique_cve_package_pairs"]) for v in scan["sbom"]})
    mis_i = scan["dockerfile_misconfigurations"].get("insecure", [])
    mis_h = scan["dockerfile_misconfigurations"].get("hardened", [])
    check("scan: Trivy flags the insecure Dockerfile (root user, no HEALTHCHECK, secret in ENV)",
          {"DS-0002", "DS-0026", "DS-0031"} <= {m["id"] for m in mis_i}, mis_i)
    check("scan: Trivy reports nothing for the hardened Dockerfile", mis_h == [], mis_h)
    check("scan: Trivy DB timestamp recorded", bool(scan["trivy"].get("db_updated_at")), scan["trivy"])
else:
    print("SKIP  scan: Trivy was not executed (see scan/status.json)")
if scan and scan.get("sbom"):
    for variant, sbom in scan["sbom"].items():
        check(f"sbom: {variant} CycloneDX document has components", sbom["components"] > 0 and sbom["format"] == "CycloneDX", sbom)
else:
    print("SKIP  sbom: Syft was not executed (see sbom/status.json)")

sign = load("signing/summary.json")
if sign and sign.get("executed"):
    for key, want in (("signed", True), ("verify_signed_digest", True), ("unsigned_rejected", True),
                      ("wrong_key_rejected", True), ("tag_before_substitution_ok", True),
                      ("tag_substitution_rejected", True), ("attestation_verified", True),
                      ("wrong_predicate_rejected", True)):
        if key in sign["results"]:
            check(f"signing: {key}", sign["results"][key] is want, sign["results"][key])
else:
    print("SKIP  signing: cosign was not executed (see signing/status.json)")

print(f"\n{passes} passed, {len(failures)} failed")
sys.exit(1 if failures else 0)
