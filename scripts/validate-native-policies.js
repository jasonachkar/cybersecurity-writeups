#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");
const REQUIRED = process.env.REQUIRE_NATIVE_SECURITY_TOOLS === "1";
const EXPECTED_OPA_VERSION = "1.17.0";
const EXPECTED_KYVERNO_VERSION = "1.18.2";

function candidates(environmentName, localPaths, command) {
  return [
    process.env[environmentName],
    ...localPaths.map((localPath) => path.join(ROOT, ...localPath)),
    command,
  ].filter(Boolean);
}

function locate(name, executableCandidates, versionArguments, expectedVersion) {
  for (const executable of executableCandidates) {
    const result = spawnSync(executable, versionArguments, {
      cwd: ROOT,
      encoding: "utf8",
      shell: false,
      windowsHide: true,
    });
    if (result.error && result.error.code === "ENOENT") continue;
    if (result.error) {
      throw new Error(`${name} discovery failed for ${executable}: ${result.error.message}`);
    }
    const output = `${result.stdout || ""}\n${result.stderr || ""}`;
    if (result.status !== 0) {
      throw new Error(`${executable} ${versionArguments.join(" ")} failed:\n${output.trim()}`);
    }
    if (!output.includes(expectedVersion)) {
      throw new Error(
        `${name} must be version ${expectedVersion}; ${executable} reported:\n${output.trim()}`,
      );
    }
    return executable;
  }
  if (REQUIRED) {
    throw new Error(
      `${name} ${expectedVersion} is required. Set its binary path or add it to PATH.`,
    );
  }
  console.warn(
    `Validation limitation: ${name} ${expectedVersion} is unavailable; native ${name} tests were skipped.`,
  );
  return null;
}

function run(executable, args) {
  console.log(`==> ${path.basename(executable)} ${args.join(" ")}`);
  const result = spawnSync(executable, args, {
    cwd: ROOT,
    env: process.env,
    stdio: "inherit",
    shell: false,
    windowsHide: true,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${path.basename(executable)} exited with status ${result.status}`);
  }
}

function validateOpa(opa) {
  if (!opa) return;
  const policy = "labs/iac-policy/policy/terraform.rego";
  const cases = [
    ["secure_fixture_test.rego", "secure_plan.json"],
    ["insecure_fixture_test.rego", "insecure_plan.json"],
    ["unknown_fixture_test.rego", "unknown_plan.json"],
    ["deleted_fixture_test.rego", "deleted_control_plan.json"],
  ];
  for (const [testFile, fixture] of cases) {
    run(opa, [
      "test",
      policy,
      `labs/iac-policy/policy/${testFile}`,
      `labs/iac-policy/fixtures/${fixture}`,
      "-v",
    ]);
  }
}

function validateKyverno(kyverno) {
  if (!kyverno) return;
  run(kyverno, [
    "test",
    "labs/kubernetes-security",
    "--remove-color",
  ]);
  run(kyverno, [
    "apply",
    "labs/kubernetes-security/policies/verify-release-images.yaml",
    "--resource",
    "labs/kubernetes-security/fixtures/pods.yaml",
    "--remove-color",
  ]);
}

try {
  const opa = locate(
    "OPA",
    candidates(
      "OPA_BIN",
      process.platform === "win32"
        ? [[".tools", "opa.exe"]]
        : [[".tools", "opa"]],
      process.platform === "win32" ? "opa.exe" : "opa",
    ),
    ["version"],
    EXPECTED_OPA_VERSION,
  );
  const kyverno = locate(
    "Kyverno",
    candidates(
      "KYVERNO_BIN",
      process.platform === "win32"
        ? [
          [".tools", "kyverno-1.18.2", "kyverno.exe"],
          [".tools", "kyverno.exe"],
        ]
        : [
          [".tools", "kyverno-1.18.2", "kyverno"],
          [".tools", "kyverno"],
        ],
      process.platform === "win32" ? "kyverno.exe" : "kyverno",
    ),
    ["version"],
    EXPECTED_KYVERNO_VERSION,
  );
  validateOpa(opa);
  validateKyverno(kyverno);
  console.log("PASS: available pinned native policy engines validated their fixtures.");
} catch (error) {
  console.error(`Native policy validation failed: ${error.message}`);
  process.exit(1);
}
