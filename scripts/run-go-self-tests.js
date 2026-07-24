#!/usr/bin/env node
"use strict";

const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");
const required = process.env.REQUIRE_CODE_TOOLCHAINS === "1";
const executable = process.env.GO_BIN ||
  (process.platform === "win32" ? "go.exe" : "go");
const version = spawnSync(executable, ["version"], {
  cwd: ROOT,
  encoding: "utf8",
  shell: false,
  windowsHide: true,
});

if (version.error && version.error.code === "ENOENT") {
  const message = "Go toolchain unavailable; executable Go self-tests were skipped.";
  if (required) {
    console.error(message);
    process.exit(1);
  }
  console.warn(`Validation limitation: ${message}`);
  process.exit(0);
}
if (version.error || version.status !== 0) {
  console.error(version.error?.message || version.stderr || version.stdout);
  process.exit(1);
}

for (const file of [
  path.join("appsec", "scripts", "oauth-pkce-verifier.go"),
  path.join("devsecops", "scripts", "secret-scanner.go"),
]) {
  console.log(`\n==> go run ${file.split(path.sep).join("/")}`);
  const result = spawnSync(executable, ["run", file], {
    cwd: ROOT,
    env: process.env,
    stdio: "inherit",
    shell: false,
    windowsHide: true,
  });
  if (result.error || result.status !== 0) {
    console.error(
      result.error?.message || `${file} exited with status ${result.status}.`,
    );
    process.exit(1);
  }
}

console.log("\nPASS: 2 executable Go security self-test programs completed.");
