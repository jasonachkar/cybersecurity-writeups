#!/usr/bin/env node
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");

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

const [, , artifactPath, statementPath, policyPath] = process.argv;
if (!artifactPath || !statementPath || !policyPath) stop("usage: node verify-provenance.js <artifact> <statement.json> <policy.json>");
if (!fs.existsSync(artifactPath)) stop("artifact is missing");
const statement = readJson(statementPath);
const policy = readJson(policyPath);
const digest = crypto.createHash("sha256").update(fs.readFileSync(artifactPath)).digest("hex");

if (statement._type !== policy.statementType) stop(`unexpected statement type ${String(statement._type)}`);
if (statement.predicateType !== policy.predicateType) stop(`unexpected predicate type ${String(statement.predicateType)}`);
if (!Array.isArray(statement.subject) || statement.subject.length !== 1) stop("statement must contain exactly one subject");
if (statement.subject[0].digest?.sha256 !== digest) stop("artifact digest does not match statement subject");
if (statement.predicate?.buildDefinition?.buildType !== policy.builderId) stop("builder identity is not authorized");
if (statement.predicate?.buildDefinition?.externalParameters?.source !== policy.sourceUri) stop("source repository/ref is not authorized");
if (statement.verification?.issuer !== policy.issuer) stop("attestation issuer is not authorized");
if (statement.verification?.verified !== true) stop("fixture does not carry a successful signature-verification result");

console.log(`VERIFICATION_PASSED: digest, statement type, builder, source, and issuer matched policy (${digest}).`);
