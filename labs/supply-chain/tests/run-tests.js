"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const lab = path.resolve(__dirname, "..");
const verifier = path.join(lab, "verify-provenance.js");
const artifact = path.join(lab, "artifact", "release.txt");
const validStatement = path.join(lab, "provenance.valid.json");
const validVerifierResult = path.join(lab, "verifier-result.valid.json");
const policy = path.join(lab, "policy.json");
const temporaryDirectory = fs.mkdtempSync(
  path.join(os.tmpdir(), `supply-chain-negative-${process.pid}-`),
);

function verify(statement, verifierResult, expectedStatus, marker) {
  const result = spawnSync(
    process.execPath,
    [verifier, artifact, statement, verifierResult, policy],
    { encoding: "utf8" },
  );
  assert.equal(result.status, expectedStatus, result.stderr || result.stdout);
  assert.match(`${result.stdout}\n${result.stderr}`, marker);
}

function verifierResultFor(statement, name, overrides = {}) {
  const result = JSON.parse(fs.readFileSync(validVerifierResult, "utf8"));
  result.statement = JSON.parse(fs.readFileSync(statement, "utf8"));
  Object.assign(result, overrides);
  const output = path.join(temporaryDirectory, `${name}.verifier-result.json`);
  fs.writeFileSync(output, `${JSON.stringify(result, null, 2)}\n`, "utf8");
  return output;
}

try {
  verify(validStatement, validVerifierResult, 0, /VERIFICATION_PASSED/);
  const crlfStatement = path.join(temporaryDirectory, "provenance.valid.crlf.json");
  fs.writeFileSync(
    crlfStatement,
    fs.readFileSync(validStatement, "utf8").replace(/\r?\n/g, "\r\n"),
    "utf8",
  );
  verify(crlfStatement, validVerifierResult, 0, /VERIFICATION_PASSED/);

  const policyNegativeStatements = [
    ["provenance.bad-digest.json", /artifact digest does not match/],
    ["provenance.wrong-builder-id.json", /builder ID is not authorized/],
    ["provenance.wrong-build-type.json", /build type is not authorized/],
    ["provenance.missing-run-details.json", /runDetails is required/],
    ["provenance.wrong-source.json", /source repository\/ref is not authorized/],
  ];

  for (const [file, marker] of policyNegativeStatements) {
    const statement = path.join(lab, file);
    verify(statement, verifierResultFor(statement, file), 4, marker);
  }

  verify(
    validStatement,
    verifierResultFor(validStatement, "wrong-issuer", {
      issuer: "https://issuer.example.invalid",
    }),
    4,
    /attestation issuer is not authorized/,
  );
  verify(
    validStatement,
    verifierResultFor(validStatement, "failed-verification", { verified: false }),
    4,
    /cryptographic verification did not succeed/,
  );

  const mismatchedResult = verifierResultFor(validStatement, "mismatched-statement");
  const mismatched = JSON.parse(fs.readFileSync(mismatchedResult, "utf8"));
  mismatched.statement.subject[0].name = "different-artifact.txt";
  fs.writeFileSync(mismatchedResult, `${JSON.stringify(mismatched, null, 2)}\n`, "utf8");
  verify(validStatement, mismatchedResult, 4, /not bound to this provenance statement/);

  const temporaryArtifact = path.join(temporaryDirectory, "tampered-release.txt");
  fs.writeFileSync(temporaryArtifact, "tampered\n", "utf8");
  const tampered = spawnSync(
    process.execPath,
    [verifier, temporaryArtifact, validStatement, validVerifierResult, policy],
    { encoding: "utf8" },
  );
  assert.equal(tampered.status, 4);
  assert.match(tampered.stderr, /artifact digest does not match/);

  const sbom = JSON.parse(fs.readFileSync(path.join(lab, "sbom.cdx.json"), "utf8"));
  assert.equal(sbom.bomFormat, "CycloneDX");
  assert.equal(sbom.specVersion, "1.7");
  console.log(
    "PASS: provenance builder/build-type/source/digest policy, external-verifier, " +
      "tamper, and SBOM fixture tests completed.",
  );
} finally {
  fs.rmSync(temporaryDirectory, { recursive: true, force: true });
}
