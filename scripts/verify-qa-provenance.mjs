#!/usr/bin/env node
/**
 * Strict verification of assembled QA provenance reports.
 * Fails on missing reports, missing fields, commit mismatch, dirty tree, or non-passed result.
 */
import fs from "node:fs";
import path from "node:path";
import {execFileSync} from "node:child_process";
import {root, requireField} from "./qa-provenance.mjs";

const FRESHNESS_HOURS = 168; // one week

function git(args) {
  return execFileSync("git", args, {cwd: root, encoding: "utf8"}).trim();
}

const head = git(["rev-parse", "HEAD"]);
const tree = git(["rev-parse", "HEAD^{tree}"]);

const REPORTS = [
  "validation-report.json",
  "html-validation-report.json",
  "defect-check-report.json",
  "accessibility-report.json",
  "external-link-report.json",
  "gitleaks-report.json",
  "labs-report.json",
  "go-report.json",
  "terraform-report.json",
  "opa-report.json",
  "bicep-report.json",
  "policy-schemas-report.json",
  "kyverno-report.json",
  "postgres-report.json",
  "shell-report.json",
  "powershell-report.json",
  "verification-summary.json"
];

const REQUIRED_FIELDS = [
  "executedAt",
  "sourceCommit",
  "sourceTree",
  "validatedCommit",
  "validatedTree",
  "repository",
  "eventName",
  "ref",
  "workflowRunId",
  "workflowRunAttempt",
  "dirtyWorkingTree",
  "command",
  "toolVersions",
  "result"
];

const NON_NULL_FIELDS = [
  "executedAt",
  "sourceCommit",
  "sourceTree",
  "validatedCommit",
  "validatedTree",
  "repository",
  "eventName",
  "ref",
  "command",
  "result"
];

const errors = [];
const now = Date.now();

for (const name of REPORTS) {
  const file = path.join(root, "qa", name);
  if (!fs.existsSync(file)) {
    errors.push(`missing report: qa/${name}`);
    continue;
  }

  let report;
  try {
    report = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (error) {
    errors.push(`${name}: invalid JSON (${error.message})`);
    continue;
  }

  for (const field of REQUIRED_FIELDS) {
    if (!(field in report)) {
      errors.push(`${name}: missing field ${field}`);
    }
  }
  for (const field of NON_NULL_FIELDS) {
    try {
      requireField(report, field);
    } catch (error) {
      errors.push(`${name}: ${error.message}`);
    }
  }

  if (report.toolVersions === null || typeof report.toolVersions !== "object") {
    errors.push(`${name}: toolVersions must be a present object`);
  }

  if (typeof report.dirtyWorkingTree !== "boolean") {
    errors.push(`${name}: dirtyWorkingTree must be boolean`);
  } else if (report.dirtyWorkingTree === true) {
    errors.push(`${name}: dirtyWorkingTree is true`);
  }

  if (report.validatedCommit !== head) {
    errors.push(`${name}: validatedCommit ${report.validatedCommit} != HEAD ${head}`);
  }
  if (report.validatedTree && report.validatedTree !== tree) {
    errors.push(`${name}: validatedTree ${report.validatedTree} != ${tree}`);
  }
  if (report.sourceCommit && report.sourceCommit !== head) {
    errors.push(`${name}: sourceCommit ${report.sourceCommit} != HEAD ${head}`);
  }
  if (report.result !== "passed") {
    errors.push(`${name}: result is ${report.result ?? "(missing)"}`);
  }

  const stamp = report.executedAt;
  if (!stamp || Number.isNaN(Date.parse(stamp))) {
    errors.push(`${name}: missing/invalid executedAt`);
  } else {
    const ageHours = (now - Date.parse(stamp)) / 3_600_000;
    if (ageHours > FRESHNESS_HOURS) {
      errors.push(`${name}: stale (${ageHours.toFixed(1)}h old)`);
    }
  }
}

if (errors.length) {
  console.error("QA provenance verification failed:");
  for (const error of errors) console.error(`- ${error}`);
  process.exit(1);
}

console.log(`QA provenance verified against commit ${head} tree ${tree} (${REPORTS.length} reports).`);
