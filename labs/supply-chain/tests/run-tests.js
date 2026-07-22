"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { spawnSync } = require("node:child_process");
const lab = path.resolve(__dirname, "..");
const verifier = path.join(lab, "verify-provenance.js");
const artifact = path.join(lab, "artifact", "release.txt");
const valid = path.join(lab, "provenance.valid.json");
const policy = path.join(lab, "policy.json");

function verify(statement, expectedStatus, marker) {
  const result = spawnSync(process.execPath, [verifier, artifact, statement, policy], { encoding: "utf8" });
  assert.equal(result.status, expectedStatus, result.stderr || result.stdout);
  assert.match(`${result.stdout}\n${result.stderr}`, marker);
}

verify(valid, 0, /VERIFICATION_PASSED/);
verify(path.join(lab, "provenance.bad-digest.json"), 4, /digest does not match/);
verify(path.join(lab, "provenance.untrusted-builder.json"), 4, /builder identity/);
verify(path.join(lab, "provenance.unverified.json"), 4, /successful signature-verification/);

const temporaryArtifact = path.join(os.tmpdir(), `supply-chain-negative-${process.pid}.txt`);
fs.writeFileSync(temporaryArtifact, "tampered\n", "utf8");
try {
  const result = spawnSync(process.execPath, [verifier, temporaryArtifact, valid, policy], { encoding: "utf8" });
  assert.equal(result.status, 4);
  assert.match(result.stderr, /digest does not match/);
} finally {
  fs.rmSync(temporaryArtifact, { force: true });
}

const sbom = JSON.parse(fs.readFileSync(path.join(lab, "sbom.cdx.json"), "utf8"));
assert.equal(sbom.bomFormat, "CycloneDX");
assert.equal(sbom.specVersion, "1.7");
console.log("PASS: provenance policy, tamper, identity, verification-state, and SBOM fixture tests completed.");
