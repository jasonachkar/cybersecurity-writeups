#!/usr/bin/env node
/**
 * Stamp or assemble QA reports with commit-bound provenance.
 *
 * Modes:
 *   static      — run static validators and stamp their reports
 *   links       — run external-link check and stamp
 *   secrets     — run gitleaks dir+git and stamp structured report
 *   summary     — assemble verification-summary.json (strict gate)
 *   suite-pass  — generic passed stamp: suite-pass <report.json> [command] [extraJson]
 */
import {spawnSync} from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import {createRequire} from "node:module";
import {buildProvenance, writeQaReport, requireField, root} from "./qa-provenance.mjs";

const require = createRequire(import.meta.url);
const mode = process.argv[2];

const REQUIRED_SUMMARY_REPORTS = [
  "validation-report.json",
  "html-validation-report.json",
  "defect-check-report.json",
  "accessibility-report.json",
  "ui-layout-report.json",
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
  "powershell-report.json"
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

function runNode(script) {
  const result = spawnSync(process.execPath, [script], {cwd: root, stdio: "inherit"});
  if (result.status !== 0) process.exit(result.status ?? 1);
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function assertReportReady(name, report, expectedCommit) {
  for (const field of REQUIRED_FIELDS) {
    if (!(field in report)) {
      throw new Error(`${name}: missing required field ${field}`);
    }
  }
  // Non-nullable string/object fields
  for (const field of [
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
  ]) {
    requireField(report, field);
  }
  if (report.toolVersions === null || typeof report.toolVersions !== "object") {
    throw new Error(`${name}: toolVersions must be an object`);
  }
  if (report.result !== "passed") {
    throw new Error(`${name}: result is ${report.result}`);
  }
  if (report.dirtyWorkingTree === true) {
    throw new Error(`${name}: dirtyWorkingTree is true`);
  }
  if (report.validatedCommit !== expectedCommit) {
    throw new Error(
      `${name}: validatedCommit ${report.validatedCommit} != expected ${expectedCommit}`
    );
  }
}

function readGitleaksFindings(reportPath) {
  if (!fs.existsSync(reportPath)) return [];
  const raw = readJson(reportPath);
  if (Array.isArray(raw)) return raw;
  if (Array.isArray(raw.findings)) return raw.findings;
  return [];
}

if (mode === "static") {
  runNode("scripts/validate-gh-pages.mjs");
  runNode("scripts/run-html-validation.mjs");
  runNode("scripts/check-known-defects.mjs");
  const htmlValidate = JSON.parse(fs.readFileSync(require.resolve("html-validate/package.json"), "utf8"));
  const provenance = buildProvenance({
    command: "npm run verify:static",
    toolVersions: {node: process.version, htmlValidate: htmlValidate.version},
    result: "passed"
  });
  for (const name of ["validation-report.json", "html-validation-report.json"]) {
    const target = path.join(root, "qa", name);
    let existing = {};
    if (fs.existsSync(target)) {
      try {
        existing = readJson(target);
      } catch {
        existing = {};
      }
    }
    writeQaReport(name, {...existing, ...provenance, detailSource: name});
  }
  writeQaReport("defect-check-report.json", {
    ...provenance,
    patternsChecked: 21,
    result: "passed"
  });
  console.log("Static verification reports stamped with commit provenance.");
  process.exit(0);
}

if (mode === "links") {
  runNode("scripts/check-external-links.mjs");
  const target = path.join(root, "qa", "external-link-report.json");
  const existing = readJson(target);
  const provenance = buildProvenance({
    command: "npm run verify:links",
    toolVersions: {node: process.version},
    result: existing.counts?.broken ? "failed" : "passed"
  });
  writeQaReport("external-link-report.json", {...existing, ...provenance});
  if (provenance.result !== "passed") process.exit(1);
  process.exit(0);
}

if (mode === "secrets") {
  const version = spawnSync("gitleaks", ["version"], {encoding: "utf8", shell: false});
  if (version.error?.code === "ENOENT" || version.status !== 0) {
    console.error("gitleaks is required (install Gitleaks 8.30.0)");
    process.exit(1);
  }
  fs.mkdirSync(path.join(root, "qa-artifacts"), {recursive: true});
  const dirReport = path.join(root, "qa-artifacts", "gitleaks-dir.json");
  const gitReport = path.join(root, "qa-artifacts", "gitleaks-git.json");

  const dirScan = spawnSync(
    "gitleaks",
    ["dir", ".", "--redact", "--config", ".gitleaks.toml", "--report-path", dirReport, "--report-format", "json"],
    {cwd: root, shell: false, stdio: "inherit"}
  );
  const gitScan = spawnSync(
    "gitleaks",
    ["git", ".", "--redact", "--config", ".gitleaks.toml", "--report-path", gitReport, "--report-format", "json"],
    {cwd: root, shell: false, stdio: "inherit"}
  );

  const workingTreeFindings = readGitleaksFindings(dirReport);
  const historyFindings = readGitleaksFindings(gitReport);
  const workingTreeFindingCount = workingTreeFindings.length;
  const historyFindingCount = historyFindings.length;
  const passed =
    dirScan.status === 0 &&
    gitScan.status === 0 &&
    workingTreeFindingCount === 0 &&
    historyFindingCount === 0;

  const provenance = buildProvenance({
    command: "npm run verify:secrets",
    toolVersions: {gitleaks: (version.stdout || version.stderr || "").trim()},
    result: passed ? "passed" : "failed"
  });
  writeQaReport("gitleaks-report.json", {
    ...provenance,
    scanScopes: ["working-tree", "git-history"],
    workingTreeFindingCount,
    historyFindingCount,
    findingCount: workingTreeFindingCount + historyFindingCount,
    workingTreeFindings,
    historyFindings
  });
  if (!passed) process.exit(1);
  console.log("Gitleaks structured report written.");
  process.exit(0);
}

if (mode === "suite-pass") {
  const reportName = process.argv[3];
  if (!reportName) {
    console.error("Usage: node scripts/stamp-qa-reports.mjs suite-pass <report.json> [command] [extraJson]");
    process.exit(2);
  }
  const command = process.argv[4] || `suite-pass ${reportName}`;
  let extra = {};
  if (process.argv[5]) {
    try {
      extra = JSON.parse(process.argv[5]);
    } catch (error) {
      console.error(`Invalid extra JSON: ${error.message}`);
      process.exit(2);
    }
  }
  const provenance = buildProvenance({
    command,
    toolVersions: {node: process.version},
    result: "passed",
    extra
  });
  writeQaReport(reportName, provenance);
  console.log(`Stamped ${reportName} as passed.`);
  process.exit(0);
}

if (mode === "summary") {
  const provenance = buildProvenance({
    command: "npm run verify:all",
    toolVersions: {node: process.version},
    result: "passed"
  });
  const requiredChecks = {};
  let failed = false;

  for (const name of REQUIRED_SUMMARY_REPORTS) {
    const file = path.join(root, "qa", name);
    if (!fs.existsSync(file)) {
      requiredChecks[name] = "missing";
      failed = true;
      continue;
    }
    let report;
    try {
      report = readJson(file);
    } catch (error) {
      requiredChecks[name] = `invalid-json:${error.message}`;
      failed = true;
      continue;
    }
    try {
      assertReportReady(name, report, provenance.validatedCommit);
      requiredChecks[name] = "passed";
    } catch (error) {
      requiredChecks[name] = error.message;
      failed = true;
    }
  }

  if (failed) provenance.result = "failed";

  writeQaReport("verification-summary.json", {
    ...provenance,
    requiredChecks,
    knownLimitations: [
      "Kyverno image policy is schema/offline validated; live signature admission was not executed.",
      "Tetragon policy is schema-validated only; no live cluster enforcement.",
      "Supply-chain lab tests the offline adapter contract, not production DSSE verification.",
      "AI ApprovalStore is an in-memory teaching CAS, not a distributed durable store.",
      "PowerShell suite performs syntax parse only; the script is not executed.",
      "No cloud resources were deployed during validation."
    ]
  });

  if (failed) {
    console.error("verification-summary.json written with failures:");
    for (const [name, status] of Object.entries(requiredChecks)) {
      if (status !== "passed") console.error(`- ${name}: ${status}`);
    }
    process.exit(1);
  }
  console.log("verification-summary.json written.");
  process.exit(0);
}

console.error(`Unknown mode: ${mode || "(missing)"}`);
console.error("Modes: static | links | secrets | summary | suite-pass");
process.exit(2);
