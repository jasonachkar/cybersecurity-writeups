"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const fixtures = path.resolve(__dirname, "..", "fixtures");

function read(name) {
  return fs.readFileSync(path.join(fixtures, name), "utf8");
}

function remoteActionReferences(text) {
  return [...text.matchAll(/^\s*(?:-\s*)?uses:\s*([^\s#]+).*$/gm)]
    .map((match) => match[1])
    .filter((reference) => !reference.startsWith("./"));
}

function audit(text) {
  const findings = new Set();
  const actionReferences = remoteActionReferences(text);

  if (actionReferences.some((reference) => !/@[0-9a-f]{40}$/.test(reference))) {
    findings.add("mutable-action-reference");
  }

  if (/^\s*permissions:\s*write-all\s*$/m.test(text)) {
    findings.add("broad-workflow-permissions");
  }

  if (
    /\bpull_request_target\b/.test(text)
    && /github\.event\.pull_request\.head\.sha/.test(text)
    && /^\s*-\s*run:/m.test(text)
  ) {
    findings.add("privileged-pr-event-executes-untrusted-code");
  }

  if (
    /\bpull_request:\s*$/m.test(text)
    && !/\bworkflow_run:\s*$/m.test(text)
    && (/id-token:\s*write/.test(text) || /secrets\./.test(text))
  ) {
    findings.add("untrusted-validation-has-credential-capability");
  }

  const cloudAuthentication = text.indexOf("uses: azure/login@");
  const deployCommand = text.search(/^\s*(?:run:\s*)?(?:\.\/.*deploy|az\s+(?:deployment|webapp|containerapp)\b)/m);
  const privilegedUse = cloudAuthentication >= 0 ? cloudAuthentication : deployCommand;

  if (privilegedUse >= 0) {
    const digestVerification = text.indexOf("sha256sum --check");
    const provenanceVerification = text.indexOf("gh attestation verify");

    if (digestVerification < 0 || digestVerification > privilegedUse) {
      findings.add("digest-not-verified-before-privileged-use");
    }
    if (provenanceVerification < 0 || provenanceVerification > privilegedUse) {
      findings.add("provenance-not-verified-before-privileged-use");
    }
    if (!/^\s*environment:\s*(?:$|[^\n]+)/m.test(text)) {
      findings.add("protected-environment-not-bound");
    }
  }

  if (cloudAuthentication >= 0 && !/id-token:\s*write/.test(text)) {
    findings.add("oidc-permission-missing");
  }

  if (
    /secrets\.(?:LONG_LIVED|AWS_ACCESS_KEY|AWS_SECRET|AZURE_CLIENT_SECRET|CLOUD_ACCESS|CLOUD_SECRET)/.test(text)
  ) {
    findings.add("long-lived-cloud-credential");
  }

  if (
    /\bpull_request:\s*$/m.test(text)
    && /\bworkflow_run:\s*$/m.test(text)
    && /uses:\s*actions\/cache@/.test(text)
    && /key:\s*shared-release-tools/.test(text)
  ) {
    findings.add("shared-cache-crosses-trust-boundary");
  }

  if (
    /uses:\s*actions\/cache@/.test(text)
    && /run:\s*\.\/\.pipeline-tools\/promote/.test(text)
  ) {
    findings.add("privileged-job-executes-cache-content");
  }

  return findings;
}

function expectNoFinding(findings, name, context) {
  assert.equal(
    findings.has(name),
    false,
    `${context}: unexpected ${name}; found ${[...findings].sort().join(", ")}`
  );
}

function expectFinding(findings, name, context) {
  assert.equal(
    findings.has(name),
    true,
    `${context}: expected ${name}; found ${[...findings].sort().join(", ")}`
  );
}

const safePullRequest = read("safe-pr.yml");
const safePullRequestFindings = audit(safePullRequest);
assert.match(safePullRequest, /^\s*pull_request:\s*$/m);
assert.doesNotMatch(safePullRequest, /\bpull_request_target\b/);
assert.match(safePullRequest, /^\s*permissions:\s*\n\s+contents:\s*read\s*$/m);
assert.doesNotMatch(safePullRequest, /\b(?:environment|id-token):/);
assert.doesNotMatch(safePullRequest, /secrets\./);
expectNoFinding(safePullRequestFindings, "mutable-action-reference", "safe PR fixture");
expectNoFinding(
  safePullRequestFindings,
  "untrusted-validation-has-credential-capability",
  "safe PR fixture"
);

const trustedRelease = read("trusted-build-release.workflow.yml");
const trustedReleaseFindings = audit(trustedRelease);
assert.ok(remoteActionReferences(trustedRelease).length >= 5);
assert.match(trustedRelease, /name:\s*release-\$\{\{\s*github\.sha\s*\}\}/);
assert.match(trustedRelease, /if-no-files-found:\s*error/);
assert.match(trustedRelease, /environment:\s*\n\s+name:\s*production/);
assert.match(trustedRelease, /id-token:\s*write/);
assert.match(trustedRelease, /uses:\s*azure\/login@[0-9a-f]{40}/);
assert.doesNotMatch(trustedRelease, /secrets\./);
assert.doesNotMatch(trustedRelease, /uses:\s*actions\/cache@/);
for (const finding of [
  "mutable-action-reference",
  "broad-workflow-permissions",
  "digest-not-verified-before-privileged-use",
  "provenance-not-verified-before-privileged-use",
  "protected-environment-not-bound",
  "oidc-permission-missing",
  "long-lived-cloud-credential",
]) {
  expectNoFinding(trustedReleaseFindings, finding, "trusted release fixture");
}

const unsafePullRequestTarget = read("unsafe-pr-target.workflow.yaml.txt");
const unsafePullRequestTargetFindings = audit(unsafePullRequestTarget);
expectFinding(
  unsafePullRequestTargetFindings,
  "privileged-pr-event-executes-untrusted-code",
  "unsafe pull_request_target fixture"
);
expectFinding(
  unsafePullRequestTargetFindings,
  "mutable-action-reference",
  "unsafe pull_request_target fixture"
);
expectFinding(
  unsafePullRequestTargetFindings,
  "broad-workflow-permissions",
  "unsafe pull_request_target fixture"
);

const unsafeConsumer = read("unsafe-privileged-consumer.workflow.yaml.txt");
const unsafeConsumerFindings = audit(unsafeConsumer);
for (const finding of [
  "mutable-action-reference",
  "broad-workflow-permissions",
  "digest-not-verified-before-privileged-use",
  "provenance-not-verified-before-privileged-use",
  "protected-environment-not-bound",
  "long-lived-cloud-credential",
]) {
  expectFinding(unsafeConsumerFindings, finding, "unsafe artifact consumer fixture");
}

const unsafeCache = read("unsafe-shared-cache.workflow.yaml.txt");
const unsafeCacheFindings = audit(unsafeCache);
for (const finding of [
  "mutable-action-reference",
  "broad-workflow-permissions",
  "shared-cache-crosses-trust-boundary",
  "privileged-job-executes-cache-content",
]) {
  expectFinding(unsafeCacheFindings, finding, "unsafe shared-cache fixture");
}

console.log(
  "PASS: 7 CI/CD boundaries accepted the hardened fixtures and rejected their unsafe counterparts."
);
