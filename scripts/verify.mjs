#!/usr/bin/env node
import {spawnSync} from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import {root} from "./qa-provenance.mjs";

function run(command, args, options = {}) {
  console.log(`\n→ ${command} ${args.join(" ")}`);
  const result = spawnSync(command, args, {
    cwd: options.cwd || root,
    stdio: "inherit",
    shell: process.platform === "win32",
    env: process.env
  });
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

function requireTool(command, versionArgs = ["--version"]) {
  const result = spawnSync(command, versionArgs, {
    cwd: root,
    encoding: "utf8",
    shell: process.platform === "win32"
  });
  if (result.status !== 0) {
    console.error(`Required tool missing: ${command}`);
    console.error(`Install it, then re-run npm run verify:all.`);
    process.exit(1);
  }
  return (result.stdout || result.stderr || "").trim().split(/\r?\n/)[0];
}

const suite = process.argv[2] || "all";

if (suite === "static" || suite === "all") {
  run("node", ["scripts/validate-gh-pages.mjs"]);
  run("node", ["scripts/run-html-validation.mjs"]);
  run("node", ["scripts/check-known-defects.mjs"]);
}

if (suite === "labs" || suite === "all") {
  run("node", ["--test", "labs/ai-agent-security/tests/broker.test.js"]);
  run("node", ["--test", "labs/oauth-oidc/tests/oauth-security.test.js"]);
  run("node", ["--test", "labs/secure-cicd/tests/policy-tests.js"]);
  run("node", ["labs/secure-cicd/tests/run-tests.js"]);
  run("node", ["--test", "labs/kubernetes-security/tests/run-tests.js"]);
  run("node", ["--test", "labs/supply-chain/tests/run-tests.js"]);
  run("node", ["labs/iam-oidc/tests/run-tests.js"]);
  run("node", ["labs/iac-policy/tests/run-tests.js"]);
}

if (suite === "go" || suite === "all") {
  requireTool("go", ["version"]);
  const modules = [
    "appsec/scripts/oauth-pkce",
    "threat-intel/scripts/cloudtrail",
    "cloud-security/scripts/k8s-rbac"
  ];
  for (const mod of modules) {
    run("gofmt", ["-w", "."], {cwd: path.join(root, mod)});
    run("go", ["test", "./..."], {cwd: path.join(root, mod)});
    run("go", ["vet", "./..."], {cwd: path.join(root, mod)});
  }
}

if (suite === "terraform" || suite === "all") {
  const tfDirs = [
    "labs/iac-policy/terraform/hardened",
    "labs/iac-policy/terraform/insecure"
  ].filter((dir) => fs.existsSync(path.join(root, dir)));
  if (tfDirs.length) {
    requireTool("terraform", ["version"]);
    for (const dir of tfDirs) {
      run("terraform", ["fmt", "-check", "-recursive"], {cwd: path.join(root, dir)});
      run("terraform", ["init", "-backend=false", "-input=false"], {cwd: path.join(root, dir)});
      run("terraform", ["validate"], {cwd: path.join(root, dir)});
    }
  }
}

if (suite === "secrets" || suite === "all") {
  requireTool("gitleaks", ["version"]);
  run("gitleaks", ["dir", ".", "--redact", "--report-path", "qa/gitleaks-report.json", "--report-format", "json"]);
}

console.log(`\nverify:${suite} completed successfully.`);
