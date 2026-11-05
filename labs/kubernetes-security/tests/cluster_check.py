#!/usr/bin/env python3
"""Assert the OBSERVED results of the Kubernetes cluster lab. Usage: cluster_check.py <outdir>

Reads what scripts/run-cluster-lab.sh recorded and fails (exit 1) when an observed
value differs from a claim made in the README. It also assembles the per-engine
admission matrix and compares it with admission-cases/expectations.json, which was
written before the engines were run. A mismatch is reported, never overwritten.
"""
import json
import pathlib
import re
import sys
from collections import defaultdict

out = pathlib.Path(sys.argv[1])
lab = pathlib.Path(__file__).resolve().parents[1]
failures, passes = [], 0


def load(name):
    path = out / name
    return json.loads(path.read_text()) if path.exists() else None


def jsonl(name):
    path = out / name
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()] if path.exists() else []


def check(name, condition, detail=""):
    global passes
    if condition:
        passes += 1
        print(f"PASS  {name}")
    else:
        failures.append(name)
        print(f"FAIL  {name}  {detail}")


def calls(report):
    return {c["name"]: c for c in report.get("api_calls", [])}



# ---- environment gate ---------------------------------------------------------------
smoke = load("np-smoke.json")
check("NetworkPolicy is enforced by this cluster's CNI (precondition for every network result)",
      bool(smoke) and smoke["networkpolicy_enforced"] is True, smoke)

# ---- baseline: identity -------------------------------------------------------------
bk = load("baseline-k8sprobe.json")
check("baseline: token mounted by default", bool(bk) and bk["token_mounted"] is True)
if bk:
    c = calls(bk)
    check("baseline: token is a bound (pod-scoped) token", bk["token_claims"].get("bound_to_pod") is True, bk["token_claims"])
    for name in ("list_secrets_kube_system", "list_pods_all_namespaces", "list_nodes", "list_secrets_own_ns", "list_configmaps_own_ns"):
        check(f"baseline: {name} returns 200", c.get(name, {}).get("status") == 200, c.get(name))
    check("baseline: kube-system secrets are listable (count only, no names or values recorded)",
          (c["list_secrets_kube_system"].get("items") or 0) > 0, c["list_secrets_kube_system"])
    acc = bk["self_subject_access_review"]
    for name in ("create_pods_own_ns", "create_pods_exec_own_ns", "get_secrets_any_namespace", "create_rolebindings_own_ns"):
        check(f"baseline: SelfSubjectAccessReview allows {name}", acc.get(name) is True, acc)
    for name in ("escalate_clusterroles", "impersonate_users"):
        check(f"baseline: {name} is NOT allowed (the over-grant is bounded, not cluster-admin)", acc.get(name) is False, acc)
bc = load("baseline-can-i.json")
check("baseline: kubectl auth can-i agrees with the in-pod review",
      bool(bc) and bc.get("get secrets in kube-system") is True and bc.get("create pods/exec in lab-data") is True
      and bc.get("escalate clusterroles (any namespace)") is False, bc)

# ---- baseline: runtime and network --------------------------------------------------
bp = load("baseline-posture.json")
if bp:
    p, pr = bp["posture"], {x["name"].split(" ")[0]: x for x in bp["probes"]}
    check("baseline: runs as uid 0", p["uid"] == 0)
    check("baseline: privileged container has a large capability set", len(p["cap_eff"]) >= 30, len(p["cap_eff"]))
    check("baseline: no seccomp filter", p["seccomp_mode"] == "0", p["seccomp_mode"])
    check("baseline: host PID namespace visible", p["visible_process_count"] > 10, p["visible_process_count"])
    check("baseline: root filesystem writable", pr["write_root_filesystem"]["allowed"] is True)
    check("baseline: hostPath directory writable from the container", pr["host_canary_write"]["allowed"] is True)
owner = out / "baseline-hostpath-owner.txt"
check("baseline: file written through hostPath is owned by uid 0 on the node",
      owner.exists() and owner.read_text().split()[0] == "0", owner.read_text() if owner.exists() else None)
bn = {(l["to"].split(".")[0]): l["result"] for l in jsonl("baseline-net.jsonl")}
for target in ("canary", "neighbor"):
    check(f"baseline: pod reaches {target} (no NetworkPolicy)", bn.get(target, {}).get("connected") is True, bn.get(target))
api_conn = [l["result"] for l in jsonl("baseline-net.jsonl") if l["to"].endswith(":6443")]
check("baseline: pod reaches the API server endpoint directly", bool(api_conn) and api_conn[0]["connected"] is True, api_conn)

# ---- admission matrix ---------------------------------------------------------------
expect = json.loads((lab / "admission-cases" / "expectations.json").read_text())["cases"]
base = load("matrix-lab-baseline.json")
psa = load("matrix-lab-hardened-psa.json")
vap = load("matrix-lab-vap-only.json")
comb = load("matrix-lab-hardened-combined.json")
check("admission: all matrices recorded", all([base, psa, vap, comb]))
if all([base, psa, vap, comb]):
    n = len(expect)
    allowed = sum(1 for r in base["results"].values() if r["decision"] == "allow")
    check(f"baseline admission: all {n} cases admitted (no admission control)", allowed == n, {k: v for k, v in base["results"].items() if v["decision"] != "allow"})

    # Kyverno CLI (offline): the test file encodes the predicted results; check the CLI agrees.
    kv_text = (out / "kyverno-test.txt").read_text() if (out / "kyverno-test.txt").exists() else ""
    m = re.search(r"Test Summary: (\d+) tests? passed and (\d+) tests? failed", kv_text)
    check("kyverno: every predicted result matched the CLI", bool(m) and m.group(2) == "0", m.group(0) if m else kv_text[:200])
    # OPA (offline)
    opa_cases = load("opa-cases.json")
    opa_deny = defaultdict(set)
    if opa_cases:
        for v in opa_cases["result"][0]["expressions"][0]["value"]:
            opa_deny[v["object"].split("/", 1)[1]].add(v["rule"])

    rows, mismatches = [], []
    for case, want in expect.items():
        got = {
            "psa": psa["results"][case]["decision"],
            "vap": vap["results"][case]["decision"],
            "opa": "deny" if opa_deny.get(case) else "allow",
            # kyverno decision = predicted result, valid only because the CLI matched all of them
            "kyverno": want["kyverno"],
        }
        combined = comb["results"][case]["decision"]
        for engine in ("psa", "vap", "opa", "kyverno"):
            if got[engine] != want[engine]:
                mismatches.append((case, engine, want[engine], got[engine]))
        union_expected = "deny" if (got["psa"] == "deny" or got["vap"] == "deny") else "allow"
        rows.append((case, got, combined, union_expected))
        check(f"matrix: {case}: combined PSA+VAP decision equals deny-if-either", combined == union_expected, (combined, union_expected))
    for engine in ("psa", "vap", "opa"):
        bad = [m for m in mismatches if m[1] == engine]
        check(f"matrix: live/offline {engine} decisions match the predictions in expectations.json", not bad, bad)
    psa_only = [r[0] for r in rows if r[1]["psa"] == "deny" and r[1]["vap"] == "allow"]
    vap_only = [r[0] for r in rows if r[1]["vap"] == "deny" and r[1]["psa"] == "allow"]
    check("matrix: neither PSA nor VAP alone covers the corpus (each denies cases the other allows)", bool(psa_only) and bool(vap_only), (psa_only, vap_only))

    lines = ["| Case | PSA restricted (live) | VAP (live) | PSA+VAP together (live) | Kyverno hardened-pods (offline) | OPA workload.rego (offline) |", "| --- | --- | --- | --- | --- | --- |"]
    for case, got, combined, _ in rows:
        lines.append(f"| `{case}` | {got['psa']} | {got['vap']} | {combined} | {'allow' if got['kyverno'] == 'pass' else 'deny'} | {got['opa']} |")
    (out / "matrix-table.txt").write_text("\n".join(lines) + "\n")
    (out / "matrix.json").write_text(json.dumps({"cases": {c: {**g, "combined": cb} for c, g, cb, _ in rows}, "mismatches": mismatches}, indent=2) + "\n")
    if mismatches:
        print("INFO  mismatches against the pre-run predictions:", mismatches)

rej = (out / "hardened-rejects-baseline-workload.txt")
text = rej.read_text() if rej.exists() else ""
check("hardened: submitting the unchanged baseline Deployment warns (PSA enforce applies to Pods, not Deployments)",
      "would violate PodSecurity" in text and "restricted" in text, text[:300])
check("hardened: the ReplicaSet's pod creation is refused by Pod Security Admission and no pod exists",
      'violates PodSecurity "restricted' in text.split("persisted")[-1] and "pods_created_by_deployment=0" in text, text[-600:])

# ---- hardened: identity --------------------------------------------------------------
ha = load("hardened-app-k8sprobe.json")
check("hardened app: no API token mounted at all", bool(ha) and ha["token_mounted"] is False, ha)
hr = load("hardened-apireader-k8sprobe.json")
check("hardened api-reader: has a token", bool(hr) and hr["token_mounted"] is True)
if hr:
    c = calls(hr)
    check("hardened api-reader: GET of its one ConfigMap succeeds", c["get_configmap_app_config_own_ns"]["status"] == 200, c["get_configmap_app_config_own_ns"])
    for name in ("list_configmaps_own_ns", "list_secrets_own_ns", "list_secrets_kube_system", "list_pods_all_namespaces", "list_nodes"):
        check(f"hardened api-reader: {name} is forbidden (403)", c[name]["status"] == 403, c[name])
    check("hardened api-reader: every probed write/escalation review is denied", not any(hr["self_subject_access_review"].values()), hr["self_subject_access_review"])
    claims = hr["token_claims"]
    check("hardened api-reader: token is bound to a pod", claims.get("bound_to_pod") is True, claims)
    check("hardened api-reader: token lifetime is at most the requested 3600 seconds", 0 < claims.get("seconds_until_expiry", 0) <= 3600, claims)
check("hardened api-reader: can-i get app-config -> yes", (out / "hardened-can-i-app-config.txt").read_text().strip() == "yes" if (out / "hardened-can-i-app-config.txt").exists() else False)
check("hardened api-reader: can-i get unrelated-config -> no (resourceNames scoping)", (out / "hardened-can-i-unrelated-config.txt").read_text().strip() == "no" if (out / "hardened-can-i-unrelated-config.txt").exists() else False)

# ---- hardened: runtime and network ------------------------------------------------------
hp = load("hardened-posture.json")
if hp:
    p, pr = hp["posture"], {x["name"].split(" ")[0]: x for x in hp["probes"]}
    check("hardened: runs as uid 65532", p["uid"] == 65532, p["uid"])
    check("hardened: no effective capabilities", p["cap_eff"] == [], p["cap_eff"])
    check("hardened: no_new_privs set", p["no_new_privs"] == "1", p["no_new_privs"])
    check("hardened: seccomp RuntimeDefault active", p["seccomp_mode"] == "2", p["seccomp_mode"])
    check("hardened: root filesystem read-only", p["root_fs_mounted_read_only"] is True)
    check("hardened: memory limit 128 MiB applied by the kubelet", p["memory_limit"].startswith("134217728"), p["memory_limit"])
    check("hardened: own PID namespace", p["visible_process_count"] < 10 and p["pid1_comm"] == "posture", (p["pid1_comm"], p["visible_process_count"]))
    for name, errno in (("write_root_filesystem", "EROFS"), ("chown_to_other_uid", "EPERM"), ("mknod_char_device", "EPERM"),
                        ("raw_socket", "EPERM"), ("mount_tmpfs", "EPERM"), ("clone_new_user_namespace", "EPERM")):
        check(f"hardened: {name} denied with {errno}", pr[name]["allowed"] is False and pr[name]["errno"] == errno, pr[name])
    check("hardened: hostPath not mounted", pr["host_canary_mounted"]["allowed"] is False)
hn = {(l["from"], l["to"].split(".")[0].split(":")[0]): l["result"] for l in jsonl("hardened-net.jsonl")}
check("hardened app -> data-tier canary: allowed by the one explicit rule", hn.get(("hardened/app", "canary"), {}).get("connected") is True, hn)
check("hardened app -> neighbor tenant: blocked", hn.get(("hardened/app", "neighbor"), {}).get("connected") is False, hn)
api = [l["result"] for l in jsonl("hardened-net.jsonl") if l["from"] == "hardened/app" and l["to"].endswith(":6443")]
check("hardened app -> API server: blocked at the network layer too", bool(api) and api[0]["connected"] is False, api)
check("hardened api-reader -> data-tier canary: blocked (its only egress is DNS and the API server)", hn.get(("hardened/api-reader", "canary"), {}).get("connected") is False, hn)
after = jsonl("baseline-net-after-data-policy.jsonl")
check("baseline pod -> data tier: blocked after the data tier gained an ingress policy", bool(after) and after[0]["result"]["connected"] is False, after)

for label, name in (("baseline", "baseline-can-i-rule-count.txt"), ("hardened api-reader", "hardened-apireader-can-i-rule-count.txt")):
    if (out / name).exists():
        print(f"INFO  rules listed by `auth can-i --list` ({label}): {(out / name).read_text().strip()} (includes the discovery rules every identity has)")

print(f"\n{passes} passed, {len(failures)} failed")
sys.exit(1 if failures else 0)
