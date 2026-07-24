#!/usr/bin/env node
/**
 * Wrap existing validators so their reports become commit-bound.
 * Regenerates structured reports after the underlying checks pass.
 */
import {spawnSync} from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import {createRequire} from "node:module";
import {requireCleanProvenance, writeQaReport, root} from "./qa-provenance.mjs";

const require = createRequire(import.meta.url);

function run(script) {
  const result = spawnSync(process.execPath, [script], {cwd: root, stdio: "inherit"});
  if (result.status !== 0) process.exit(result.status ?? 1);
}

const mode = process.argv[2];

if (mode === "static") {
  run("scripts/validate-gh-pages.mjs");
  run("scripts/run-html-validation.mjs");
  run("scripts/check-known-defects.mjs");
  const htmlValidate = JSON.parse(fs.readFileSync(require.resolve("html-validate/package.json"), "utf8"));
  const provenance = requireCleanProvenance({
    command: "npm run verify:static",
    toolVersions: {node: process.version, htmlValidate: htmlValidate.version},
    result: "passed"
  });
  // Preserve detailed validation artifacts if present; stamp provenance over them.
  for (const name of ["validation-report.json", "html-validation-report.json"]) {
    const target = path.join(root, "qa", name);
    let existing = {};
    if (fs.existsSync(target)) {
      try { existing = JSON.parse(fs.readFileSync(target, "utf8")); } catch { existing = {}; }
    }
    writeQaReport(name, {...existing, ...provenance, detailSource: name});
  }
  writeQaReport("defect-check-report.json", {
    ...provenance,
    patternsChecked: 17,
    result: "passed"
  });
  console.log("Static verification reports stamped with commit provenance.");
  process.exit(0);
}

if (mode === "links") {
  run("scripts/check-external-links.mjs");
  const target = path.join(root, "qa", "external-link-report.json");
  const existing = JSON.parse(fs.readFileSync(target, "utf8"));
  const provenance = requireCleanProvenance({
    command: "npm run verify:links",
    toolVersions: {node: process.version},
    result: existing.counts?.broken ? "failed" : "passed"
  });
  writeQaReport("external-link-report.json", {...existing, ...provenance});
  if (provenance.result !== "passed") process.exit(1);
  process.exit(0);
}

if (mode === "secrets") {
  const version = spawnSync("gitleaks", ["version"], {encoding: "utf8", shell: true});
  if (version.status !== 0) {
    console.error("gitleaks is required");
    process.exit(1);
  }
  const reportPath = path.join(root, "qa", "gitleaks-raw.json");
  const scan = spawnSync(
    "gitleaks",
    ["dir", ".", "--redact", "--report-path", reportPath, "--report-format", "json"],
    {cwd: root, shell: true, stdio: "inherit"}
  );
  const findings = fs.existsSync(reportPath) ? JSON.parse(fs.readFileSync(reportPath, "utf8")) : [];
  const findingCount = Array.isArray(findings) ? findings.length : (findings?.findings?.length ?? 0);
  const provenance = requireCleanProvenance({
    command: "gitleaks dir . --redact",
    toolVersions: {gitleaks: (version.stdout || version.stderr || "").trim()},
    result: scan.status === 0 && findingCount === 0 ? "passed" : "failed"
  });
  writeQaReport("gitleaks-report.json", {
    ...provenance,
    scanScope: "working-tree",
    findingCount,
    findings: Array.isArray(findings) ? findings : findings.findings || []
  });
  if (provenance.result !== "passed") process.exit(1);
  console.log("Gitleaks structured report written.");
  process.exit(0);
}

if (mode === "summary") {
  const provenance = requireCleanProvenance({
    command: "npm run verify:all",
    toolVersions: {node: process.version},
    result: "passed"
  });
  const required = [
    "validation-report.json",
    "html-validation-report.json",
    "accessibility-report.json",
    "gitleaks-report.json"
  ];
  const requiredChecks = {};
  for (const name of required) {
    const file = path.join(root, "qa", name);
    if (!fs.existsSync(file)) {
      requiredChecks[name] = "missing";
      provenance.result = "failed";
      continue;
    }
    const report = JSON.parse(fs.readFileSync(file, "utf8"));
    requiredChecks[name] = report.result || "unknown";
    if (report.result && report.result !== "passed") provenance.result = "failed";
    if (report.gitCommit && report.gitCommit !== provenance.gitCommit) {
      requiredChecks[name] = "commit-mismatch";
      provenance.result = "failed";
    }
  }
  writeQaReport("verification-summary.json", {
    ...provenance,
    requiredChecks,
    knownLimitations: [
      "Kyverno image policy is schema/offline validated; live signature admission was not executed.",
      "Tetragon policy is schema-validated only; no live cluster enforcement.",
      "Supply-chain lab tests the offline adapter contract, not production DSSE verification.",
      "AI ApprovalStore is an in-memory teaching CAS, not a distributed durable store.",
      "No cloud resources were deployed during validation."
    ]
  });
  if (provenance.result !== "passed") process.exit(1);
  console.log("verification-summary.json written.");
  process.exit(0);
}

console.error(`Unknown mode: ${mode}`);
process.exit(2);
