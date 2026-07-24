#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");
const LABS = path.join(ROOT, "labs");
const executableName = /^(?:run-tests|policy-tests)\.js$|\.test\.js$/;
const testFiles = [];

for (const labEntry of fs.readdirSync(LABS, { withFileTypes: true })
  .sort((left, right) => left.name.localeCompare(right.name, "en"))) {
  if (!labEntry.isDirectory()) continue;
  const testsDirectory = path.join(LABS, labEntry.name, "tests");
  if (!fs.existsSync(testsDirectory)) continue;
  for (const testEntry of fs.readdirSync(testsDirectory, { withFileTypes: true })
    .sort((left, right) => left.name.localeCompare(right.name, "en"))) {
    if (testEntry.isFile() && executableName.test(testEntry.name)) {
      testFiles.push(path.join(testsDirectory, testEntry.name));
    }
  }
}

if (!testFiles.length) {
  console.error("No executable JavaScript lab tests were discovered.");
  process.exit(1);
}

for (const testFile of testFiles) {
  const relative = path.relative(ROOT, testFile).split(path.sep).join("/");
  console.log(`\n==> ${relative}`);
  const result = spawnSync(process.execPath, [testFile], {
    cwd: ROOT,
    env: process.env,
    stdio: "inherit",
    shell: false,
    windowsHide: true,
  });
  if (result.error) {
    console.error(`Failed to run ${relative}: ${result.error.message}`);
    process.exit(1);
  }
  if (result.status !== 0) {
    console.error(`${relative} exited with status ${result.status}.`);
    process.exit(result.status || 1);
  }
}

console.log(`\nPASS: ${testFiles.length} JavaScript lab test program(s) completed.`);
