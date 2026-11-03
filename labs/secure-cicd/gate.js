#!/usr/bin/env node
"use strict";

const fs = require("node:fs");

function fail(message, status = 2) {
  console.error(`GATE_ERROR: ${message}`);
  process.exit(status);
}

function loadJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (error) {
    fail(`cannot read valid JSON from ${file}: ${error.message}`);
  }
}

const [, , reportPath, policyPath] = process.argv;
if (!reportPath || !policyPath) fail("usage: node gate.js <report.json> <policy.json>");
const report = loadJson(reportPath);
const policy = loadJson(policyPath);

if (report.schemaVersion !== 1) fail("unsupported or missing report schemaVersion");
if (report.scanStatus !== "completed") fail(`scanner did not complete successfully (status: ${String(report.scanStatus)})`);
if (!report.findings || typeof report.findings !== "object") fail("missing findings object");

for (const severity of ["critical", "high", "secret"]) {
  const value = report.findings[severity];
  if (!Number.isInteger(value) || value < 0) fail(`findings.${severity} must be a nonnegative integer`);
}
if (!Number.isInteger(policy.maxCritical) || policy.maxCritical < 0) fail("policy.maxCritical must be a nonnegative integer");
if (!Number.isInteger(policy.maxHigh) || policy.maxHigh < 0) fail("policy.maxHigh must be a nonnegative integer");
if (typeof policy.allowSecrets !== "boolean") fail("policy.allowSecrets must be boolean");

const violations = [];
if (report.findings.critical > policy.maxCritical) violations.push(`critical findings ${report.findings.critical} exceed ${policy.maxCritical}`);
if (report.findings.high > policy.maxHigh) violations.push(`high findings ${report.findings.high} exceed ${policy.maxHigh}`);
if (!policy.allowSecrets && report.findings.secret > 0) violations.push(`secret findings ${report.findings.secret} exceed 0`);

if (violations.length) {
  console.error("GATE_BLOCKED:");
  for (const violation of violations) console.error(`- ${violation}`);
  process.exit(3);
}
console.log("GATE_PASSED: scanner completed and all policy thresholds were satisfied.");
