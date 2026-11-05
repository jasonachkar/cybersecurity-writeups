"use strict";

// Structural invariants for the baseline and hardened manifests plus consistency of
// the admission case corpus. Needs no cluster and no policy engine, so it runs in
// `npm run validate`. It is a POLICY MODEL (T1): it proves the files say what the
// README says, not that a cluster enforces them. The live and native-engine results
// come from scripts/run-cluster-lab.sh.

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const YAML = require("yaml");

const lab = path.resolve(__dirname, "..");

function load(dir) {
  const directory = path.join(lab, dir);
  return fs.readdirSync(directory).filter((f) => /\.ya?ml$/.test(f)).sort().flatMap((file) =>
    YAML.parseAllDocuments(fs.readFileSync(path.join(directory, file), "utf8")).map((d) => d.toJSON()).filter(Boolean),
  );
}
const kind = (objects, k) => objects.filter((o) => o.kind === k);
const podSpecs = (objects) => objects.filter((o) => o.kind === "Deployment").map((o) => ({ name: o.metadata.name, spec: o.spec.template.spec, meta: o.spec.template.metadata }));
const allContainers = (spec) => [...(spec.containers || []), ...(spec.initContainers || [])];

const baseline = load("baseline");
const hardened = load("hardened");

// ---- baseline: every intentional flaw is present ---------------------------------
test("baseline: the workload is privileged, root, host-PID, hostPath, unlimited, token-mounted", () => {
  const [{ spec }] = podSpecs(baseline);
  const container = spec.containers[0];
  assert.equal(container.securityContext.privileged, true);
  assert.equal(container.securityContext.runAsUser, 0);
  assert.equal(spec.hostPID, true);
  assert.ok(spec.volumes.some((v) => v.hostPath), "hostPath volume");
  assert.equal(container.resources, undefined, "no resource limits");
  assert.equal(spec.automountServiceAccountToken, undefined, "token mounted by default");
});

test("baseline: namespaces carry no Pod Security Admission labels (weak admission control)", () => {
  for (const ns of kind(baseline, "Namespace")) {
    const labels = ns.metadata.labels || {};
    assert.ok(!Object.keys(labels).some((l) => l.startsWith("pod-security.kubernetes.io/")), ns.metadata.name);
  }
});

test("baseline: no NetworkPolicy exists", () => {
  assert.equal(kind(baseline, "NetworkPolicy").length, 0);
});

test("baseline: the application identity is over-granted through a ClusterRoleBinding", () => {
  const [role] = kind(baseline, "ClusterRole");
  const resources = role.rules.flatMap((r) => r.resources);
  assert.ok(resources.includes("secrets") && resources.includes("pods/exec"));
  const [binding] = kind(baseline, "ClusterRoleBinding");
  assert.equal(binding.kind, "ClusterRoleBinding", "cluster-wide, not namespaced");
  assert.equal(binding.subjects[0].name, "app-sa");
  // Bounded on purpose: the over-grant is not cluster-admin and has no escalation verbs.
  const verbs = role.rules.flatMap((r) => r.verbs);
  assert.ok(!verbs.some((v) => ["*", "escalate", "bind", "impersonate"].includes(v)));
});

// ---- hardened: every control is declared -------------------------------------------
test("hardened: the namespace enforces, audits and warns at restricted with a pinned version", () => {
  const [ns] = kind(hardened, "Namespace");
  for (const mode of ["enforce", "audit", "warn"]) {
    assert.equal(ns.metadata.labels[`pod-security.kubernetes.io/${mode}`], "restricted");
    assert.match(ns.metadata.labels[`pod-security.kubernetes.io/${mode}-version`], /^v1\.\d+$/);
  }
});

test("hardened: every pod template meets the container-level controls", () => {
  const specs = podSpecs(hardened);
  assert.ok(specs.length >= 2);
  for (const { name, spec } of specs) {
    assert.equal(spec.securityContext.runAsNonRoot, true, name);
    assert.notEqual(spec.securityContext.runAsUser, 0, name);
    assert.equal(spec.securityContext.seccompProfile.type, "RuntimeDefault", name);
    assert.equal(spec.automountServiceAccountToken, false, `${name}: token never auto-mounted`);
    assert.ok(!spec.hostPID && !spec.hostNetwork && !spec.hostIPC, name);
    assert.ok(!(spec.volumes || []).some((v) => v.hostPath), name);
    for (const c of allContainers(spec)) {
      const sc = c.securityContext;
      assert.equal(sc.allowPrivilegeEscalation, false, `${name}/${c.name}`);
      assert.equal(sc.readOnlyRootFilesystem, true, `${name}/${c.name}`);
      assert.equal(sc.runAsNonRoot, true, `${name}/${c.name}: container-level too (the existing Kyverno policy reads only this level)`);
      assert.deepEqual(sc.capabilities.drop, ["ALL"], `${name}/${c.name}`);
      assert.ok(!sc.privileged, `${name}/${c.name}`);
      assert.ok(c.resources.limits.cpu && c.resources.limits.memory, `${name}/${c.name}`);
      assert.match(c.image, /:[^:/@]+$/, `${name}/${c.name}: explicit tag`);
      assert.ok(!c.image.endsWith(":latest"), name);
    }
  }
});

test("hardened: only the reviewed workload projects a token, short-lived, with the approval label", () => {
  const withToken = podSpecs(hardened).filter(({ spec }) =>
    (spec.volumes || []).some((v) => v.projected && v.projected.sources.some((s) => s.serviceAccountToken)));
  assert.deepEqual(withToken.map((p) => p.name), ["api-reader"]);
  const [{ spec, meta }] = withToken;
  assert.equal(meta.labels["lab.example/api-access"], "approved");
  assert.notEqual(spec.serviceAccountName, "default");
  const token = spec.volumes.find((v) => v.projected).projected.sources.find((s) => s.serviceAccountToken).serviceAccountToken;
  assert.ok(token.expirationSeconds <= 3600);
});

test("hardened: RBAC is namespaced, named-resource scoped, and wildcard-free", () => {
  assert.equal(kind(hardened, "ClusterRole").length + kind(hardened, "ClusterRoleBinding").length, 0);
  for (const role of kind(hardened, "Role")) {
    for (const rule of role.rules) {
      for (const field of ["verbs", "resources", "apiGroups"]) assert.ok(!(rule[field] || []).includes("*"), `${role.metadata.name}.${field}`);
      assert.ok(rule.resourceNames && rule.resourceNames.length > 0, `${role.metadata.name}: scoped by resourceNames`);
      assert.ok(!rule.verbs.some((v) => ["escalate", "bind", "impersonate", "create", "update", "patch", "delete"].includes(v)));
    }
  }
  for (const sa of kind(hardened, "ServiceAccount")) assert.equal(sa.automountServiceAccountToken, false, sa.metadata.name);
});

test("hardened: NetworkPolicy has a true default deny and every allow rule names a port", () => {
  const policies = kind(hardened, "NetworkPolicy");
  const denyAll = policies.find((p) => p.metadata.name === "default-deny-all");
  assert.deepEqual(denyAll.spec.podSelector, {});
  assert.deepEqual([...denyAll.spec.policyTypes].sort(), ["Egress", "Ingress"]);
  assert.equal(denyAll.spec.ingress, undefined);
  assert.equal(denyAll.spec.egress, undefined);
  for (const policy of policies.filter((p) => p !== denyAll)) {
    for (const rule of [...(policy.spec.egress || []), ...(policy.spec.ingress || [])]) {
      assert.ok(rule.ports && rule.ports.length > 0, `${policy.metadata.name}: allow rule without ports`);
      for (const peer of [...(rule.to || []), ...(rule.from || [])]) {
        assert.notEqual(peer.ipBlock && peer.ipBlock.cidr, "0.0.0.0/0", policy.metadata.name);
        assert.ok(!peer.ipBlock || /\/32$/.test(peer.ipBlock.cidr), `${policy.metadata.name}: ipBlock must be a single host`);
      }
    }
  }
});

test("hardened: the admission policy fails closed and its binding selects the enforced namespaces", () => {
  const [policy] = kind(hardened, "ValidatingAdmissionPolicy");
  const [binding] = kind(hardened, "ValidatingAdmissionPolicyBinding");
  assert.equal(policy.spec.failurePolicy, "Fail");
  assert.ok(binding.spec.validationActions.includes("Deny"));
  assert.equal(binding.spec.policyName, policy.metadata.name);
  const [ns] = kind(hardened, "Namespace");
  const selector = binding.spec.matchResources.namespaceSelector.matchLabels;
  for (const [key, value] of Object.entries(selector)) assert.equal(ns.metadata.labels[key], value);
  assert.ok(policy.spec.validations.length >= 4);
});

test("the Calico manifest pin is a SHA-256", () => {
  assert.match(fs.readFileSync(path.join(lab, "cluster", "calico.sha256"), "utf8").trim(), /^[0-9a-f]{64}$/);
});

// ---- admission case corpus consistency ------------------------------------------------
const cases = YAML.parseAllDocuments(fs.readFileSync(path.join(lab, "admission-cases", "cases.yaml"), "utf8")).map((d) => d.toJSON()).filter(Boolean);
const expectations = JSON.parse(fs.readFileSync(path.join(lab, "admission-cases", "expectations.json"), "utf8"));
const kyvernoTest = YAML.parse(fs.readFileSync(path.join(lab, "admission-cases", "kyverno-test.yaml"), "utf8"));

test("every case has exactly one expectation row, and each row names a case", () => {
  assert.deepEqual(cases.map((c) => c.metadata.name).sort(), Object.keys(expectations.cases).sort());
});

test("every case declares what it violates, and differs from compliant-app in a single concern", () => {
  const base = cases.find((c) => c.metadata.name === "compliant-app");
  for (const c of cases) assert.ok(c.metadata.annotations["lab.example/violates"], c.metadata.name);
  assert.equal(base.metadata.annotations["lab.example/violates"], "none");
});

test("the Kyverno test file lists exactly the results predicted in expectations.json", () => {
  const byResult = { pass: [], fail: [] };
  for (const r of kyvernoTest.results) byResult[r.result].push(...r.resources);
  const predicted = { pass: [], fail: [] };
  for (const [name, row] of Object.entries(expectations.cases)) predicted[row.kyverno].push(name);
  assert.deepEqual(byResult.pass.sort(), predicted.pass.sort());
  assert.deepEqual(byResult.fail.sort(), predicted.fail.sort());
});

test("expectations are well-formed", () => {
  const allowed = { psa: ["allow", "deny"], vap: ["allow", "deny"], kyverno: ["pass", "fail"], opa: ["allow", "deny"] };
  for (const [name, row] of Object.entries(expectations.cases)) {
    for (const [engine, values] of Object.entries(allowed)) assert.ok(values.includes(row[engine]), `${name}.${engine}`);
  }
});

test("the case corpus covers both layers: each admission engine denies something the other allows", () => {
  const rows = Object.values(expectations.cases);
  assert.ok(rows.some((r) => r.psa === "deny" && r.vap === "allow"));
  assert.ok(rows.some((r) => r.vap === "deny" && r.psa === "allow"));
});
