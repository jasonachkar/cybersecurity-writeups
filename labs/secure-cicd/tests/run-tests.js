"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const YAML = require("yaml");
const lab = path.resolve(__dirname, "..");
const gate = path.join(lab, "gate.js");
const policy = path.join(lab, "fixtures", "policy.json");

function expect(fixture, status, marker) {
  const result = spawnSync(process.execPath, [gate, path.join(lab, "fixtures", fixture), policy], { encoding: "utf8" });
  assert.equal(result.status, status, `${fixture}: ${result.stderr || result.stdout}`);
  assert.match(`${result.stdout}\n${result.stderr}`, marker);
}

expect("report-pass.json", 0, /GATE_PASSED/);
expect("report-critical.json", 3, /critical findings/);
expect("report-secret.json", 3, /secret findings/);
expect("report-scanner-failed.json", 2, /scanner did not complete/);
expect("report-invalid.json", 2, /nonnegative integer/);

const safeText = fs.readFileSync(path.join(lab, "fixtures", "safe-pr.yml"), "utf8");
const safe = YAML.parse(safeText);
assert.deepEqual(safe.permissions, { contents: "read" });
assert.match(safeText, /actions\/checkout@[a-f0-9]{40}/);
assert.match(safeText, /persist-credentials: false/);
assert.doesNotMatch(safeText, /pull_request_target/);

const unsafeText = fs.readFileSync(path.join(lab, "fixtures", "unsafe-pr-target.workflow.yaml.txt"), "utf8");
assert.match(unsafeText, /pull_request_target/);
assert.match(unsafeText, /permissions: write-all/);
assert.match(unsafeText, /actions\/checkout@v4/);
assert.match(unsafeText, /github\.event\.pull_request\.head\.sha/);

console.log("PASS: CI/CD gate and safe/unsafe workflow fixture tests completed.");
