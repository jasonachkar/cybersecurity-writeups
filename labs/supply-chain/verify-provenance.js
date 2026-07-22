#!/usr/bin/env node
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const { isDeepStrictEqual } = require("node:util");

const VERIFIER_RESULT_MEDIA_TYPE =
  "application/vnd.cybersecurity-writeups.provenance-verifier-result+json;version=1";

function stop(message) {
  console.error(`VERIFICATION_FAILED: ${message}`);
  process.exit(4);
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (error) {
    stop(`cannot parse ${file}: ${error.message}`);
  }
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

const [, , artifactPath, statementPath, verifierResultPath, policyPath] = process.argv;
if (!artifactPath || !statementPath || !verifierResultPath || !policyPath) {
  stop(
    "usage: node verify-provenance.js " +
      "<artifact> <statement.json> <verifier-result.json> <policy.json>",
  );
}

if (!fs.existsSync(artifactPath)) stop("artifact is missing");
const statement = readJson(statementPath);
const verifierResult = readJson(verifierResultPath);
const policy = readJson(policyPath);
const artifactDigest = sha256(fs.readFileSync(artifactPath));

if (verifierResult.mediaType !== VERIFIER_RESULT_MEDIA_TYPE) {
  stop("unsupported external verifier-result format");
}
if (!isDeepStrictEqual(verifierResult.statement, statement)) {
  stop("external verifier result is not bound to this provenance statement");
}
if (verifierResult.issuer !== policy.expectedIssuer) {
  stop("attestation issuer is not authorized");
}
if (verifierResult.verified !== true) {
  stop("external cryptographic verification did not succeed");
}

if (statement._type !== policy.statementType) {
  stop(`unexpected statement type ${String(statement._type)}`);
}
if (statement.predicateType !== policy.predicateType) {
  stop(`unexpected predicate type ${String(statement.predicateType)}`);
}
if (!Array.isArray(statement.subject) || statement.subject.length !== 1) {
  stop("statement must contain exactly one subject");
}
if (statement.subject[0].digest?.sha256 !== artifactDigest) {
  stop("artifact digest does not match statement subject");
}

const buildDefinition = statement.predicate?.buildDefinition;
if (!buildDefinition || typeof buildDefinition !== "object") {
  stop("buildDefinition is required");
}
if (buildDefinition.buildType !== policy.expectedBuildType) {
  stop("build type is not authorized");
}

const runDetails = statement.predicate?.runDetails;
if (!runDetails || typeof runDetails !== "object") {
  stop("runDetails is required");
}
if (runDetails.builder?.id !== policy.expectedBuilderId) {
  stop("builder ID is not authorized");
}

const workflowParameters = buildDefinition.externalParameters?.workflow;
const sourceFromParameters =
  workflowParameters &&
  `git+${workflowParameters.repository}@${workflowParameters.ref}`;
if (sourceFromParameters !== policy.expectedSourceUri) {
  stop("source repository/ref is not authorized");
}
const builderFromParameters =
  workflowParameters &&
  `${workflowParameters.repository}/${workflowParameters.path}@${workflowParameters.ref}`;
if (builderFromParameters !== policy.expectedBuilderId) {
  stop("workflow parameters do not match the authorized builder ID");
}

const dependencies = buildDefinition.resolvedDependencies;
if (
  !Array.isArray(dependencies) ||
  !dependencies.some((dependency) => dependency?.uri === policy.expectedSourceUri)
) {
  stop("source repository/ref is not authorized");
}

console.log(
  "VERIFICATION_PASSED: artifact digest, statement type, builder ID, build type, " +
    `source, issuer, and external verification result matched policy (${artifactDigest}).`,
);
