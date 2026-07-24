#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import {root} from "./qa-provenance.mjs";
import {execFileSync} from "node:child_process";

const FRESHNESS_HOURS = 168; // one week

function git(args) {
  return execFileSync("git", args, {cwd: root, encoding: "utf8"}).trim();
}

const head = git(["rev-parse", "HEAD"]);
const tree = git(["rev-parse", "HEAD^{tree}"]);
const reports = [
  "accessibility-report.json",
  "validation-report.json",
  "html-validation-report.json",
  "external-link-report.json",
  "gitleaks-report.json",
  "verification-summary.json"
].map((name) => path.join(root, "qa", name));

const errors = [];
const now = Date.now();

for (const file of reports) {
  if (!fs.existsSync(file)) {
    // Optional until generated in this run.
    if (path.basename(file) === "verification-summary.json") continue;
    errors.push(`missing report: ${path.relative(root, file)}`);
    continue;
  }
  let report;
  try {
    report = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (error) {
    errors.push(`${file}: invalid JSON (${error.message})`);
    continue;
  }
  if (report.gitCommit && report.gitCommit !== head) {
    errors.push(`${path.basename(file)}: gitCommit ${report.gitCommit} != HEAD ${head}`);
  }
  if (report.gitTree && report.gitTree !== tree) {
    errors.push(`${path.basename(file)}: gitTree ${report.gitTree} != ${tree}`);
  }
  if (report.dirtyWorkingTree === true) {
    errors.push(`${path.basename(file)}: dirtyWorkingTree is true`);
  }
  if (report.result && report.result !== "passed") {
    errors.push(`${path.basename(file)}: result is ${report.result}`);
  }
  const stamp = report.executedAt || report.timestamp;
  if (!stamp || Number.isNaN(Date.parse(stamp))) {
    errors.push(`${path.basename(file)}: missing/invalid executedAt`);
  } else {
    const ageHours = (now - Date.parse(stamp)) / 3_600_000;
    if (ageHours > FRESHNESS_HOURS) {
      errors.push(`${path.basename(file)}: stale (${ageHours.toFixed(1)}h old)`);
    }
  }
}

if (errors.length) {
  console.error("QA provenance verification failed:");
  for (const error of errors) console.error(`- ${error}`);
  process.exit(1);
}

console.log(`QA provenance verified against commit ${head} tree ${tree}.`);
