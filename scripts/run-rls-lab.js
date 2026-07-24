#!/usr/bin/env node
"use strict";

const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");
const labRoot = path.join(ROOT, "labs", "postgresql-rls");
const windows = process.platform === "win32";
const command = windows ? "powershell.exe" : "sh";
const args = windows
  ? [
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    path.join(labRoot, "run-tests.ps1"),
  ]
  : [path.join(labRoot, "run-tests.sh")];

const result = spawnSync(command, args, {
  cwd: ROOT,
  env: process.env,
  stdio: "inherit",
  shell: false,
  windowsHide: true,
});
if (result.error) {
  console.error(`PostgreSQL RLS lab could not start: ${result.error.message}`);
  process.exit(1);
}
if (result.status !== 0) {
  console.error(`PostgreSQL RLS lab failed with status ${result.status}.`);
  process.exit(result.status || 1);
}
console.log("PASS: PostgreSQL RLS container integration completed.");
