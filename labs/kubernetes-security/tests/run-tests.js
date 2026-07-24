"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const YAML = require("yaml");

const lab = path.resolve(__dirname, "..");
const read = (relative) => fs.readFileSync(path.join(lab, relative), "utf8");

const podPolicy = YAML.parse(read("policies/hardened-pods.yaml"));
assert.equal(podPolicy.apiVersion, "policies.kyverno.io/v1");
assert.equal(podPolicy.kind, "ValidatingPolicy");
assert.deepEqual(podPolicy.spec.validationActions, ["Deny"]);
assert.equal(podPolicy.spec.failurePolicy, "Fail");
assert.equal(podPolicy.spec.evaluation.admission.enabled, true);
assert.equal(podPolicy.spec.evaluation.background.enabled, true);

const validationText = JSON.stringify(podPolicy.spec.validations);
for (const required of [
  "hostPID",
  "hostIPC",
  "hostNetwork",
  "hostPath",
  "automountServiceAccountToken",
  "runAsNonRoot",
  "privileged",
  "allowPrivilegeEscalation",
  "readOnlyRootFilesystem",
  "capabilities",
  "seccomp",
  "requests",
  "limits",
]) {
  assert.match(validationText, new RegExp(required));
}

const imagePolicy = YAML.parse(read("policies/verify-release-images.yaml"));
assert.equal(imagePolicy.apiVersion, "policies.kyverno.io/v1");
assert.equal(imagePolicy.kind, "ImageValidatingPolicy");
assert.equal(imagePolicy.spec.failurePolicy, "Fail");
assert.deepEqual(imagePolicy.spec.validationActions, ["Deny"]);
assert.equal(imagePolicy.spec.validationConfigurations.required, true);
assert.equal(imagePolicy.spec.validationConfigurations.verifyDigest, true);
assert.equal(imagePolicy.spec.validationConfigurations.mutateDigest, true);

const imageCases = JSON.parse(read("fixtures/image-cases.json"));
const expected = imageCases.expected;
const identity = imagePolicy.spec.attestors[0].cosign.keyless.identities[0];
assert.equal(identity.issuer, expected.issuer);
assert.equal(identity.subject, expected.subject);
assert.equal(imagePolicy.spec.attestations[0].intoto.type, expected.predicateType);
assert.deepEqual(
  imagePolicy.spec.matchImageReferences.map((reference) => reference.glob),
  [`${expected.repository}:*`, `${expected.repository}@sha256:*`],
);

function matchesImageReference(reference) {
  return imagePolicy.spec.matchImageReferences.some(({ glob }) => {
    assert.match(glob, /\*$/, "the offline matcher supports reviewed trailing-star globs only");
    return reference.startsWith(glob.slice(0, -1));
  });
}

assert.equal(matchesImageReference(`${expected.repository}:release-2026-07-23`), true);
assert.equal(matchesImageReference(`${expected.repository}@${expected.digest}`), true);
assert.equal(matchesImageReference(`ghcr.io/attacker/secureobs@${expected.digest}`), false);
assert.equal(matchesImageReference(`ghcr.io/jasonachkar/secureobs-evil@${expected.digest}`), false);

function evaluate(candidate) {
  const imageDigest = candidate.image.includes("@") ? candidate.image.split("@")[1] : null;
  const repository = candidate.image.split(/[@:]/)[0];
  return (
    candidate.verifierSucceeded !== false &&
    candidate.signed === true &&
    candidate.issuer === expected.issuer &&
    candidate.subject === expected.subject &&
    repository === expected.repository &&
    candidate.predicateType === expected.predicateType &&
    candidate.provenanceValid === true &&
    imageDigest === expected.digest &&
    candidate.subjectDigest === expected.digest
  );
}

const evaluatedImageCases = imageCases.cases.filter((candidate) => candidate.accepted !== null);
for (const candidate of evaluatedImageCases) {
  assert.equal(evaluate(candidate), candidate.accepted, candidate.name);
}

const tagOnlyCase = imageCases.cases.find(
  (candidate) => candidate.name === "tag-only-reference-match",
);
assert.equal(matchesImageReference(tagOnlyCase.image), true);
assert.equal(tagOnlyCase.accepted, null);
assert.match(tagOnlyCase.matchOnlyReason, /not executed/i);

assert.deepEqual(
  evaluatedImageCases.filter((candidate) => !candidate.accepted).map((candidate) => candidate.name),
  [
    "unsigned",
    "wrong-repository",
    "wrong-workflow",
    "wrong-branch",
    "wrong-issuer",
    "missing-attestation",
    "malformed-provenance",
    "wrong-predicate",
    "verifier-or-transparency-failure",
    "tag-substitution-digest-mismatch",
  ],
);

const networkPolicies = YAML.parseAllDocuments(read("fixtures/network-policies.yaml"))
  .map((document) => document.toJSON());
const defaultDeny = networkPolicies.find(
  (policy) => policy.metadata.name === "default-deny-ingress-and-egress",
);
assert.deepEqual(defaultDeny.spec.podSelector, {});
assert.deepEqual(defaultDeny.spec.policyTypes.sort(), ["Egress", "Ingress"]);
assert.equal(defaultDeny.spec.ingress, undefined);
assert.equal(defaultDeny.spec.egress, undefined);

const dns = networkPolicies.find((policy) => policy.metadata.name === "allow-cluster-dns");
assert.deepEqual(
  dns.spec.egress[0].ports.map((port) => `${port.protocol}/${port.port}`).sort(),
  ["TCP/53", "UDP/53"],
);

console.log(
  `PASS: Kubernetes admission, image identity (${imageCases.cases.length} cases), ` +
    "and NetworkPolicy structural tests completed.",
);
