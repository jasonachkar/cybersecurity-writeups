"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const YAML = require("yaml");
const { ROOT, allRepositoryFiles, relative } = require("./content-lib");

const errors = [];
const notes = [];
const requireToolchains = process.env.REQUIRE_CODE_TOOLCHAINS === "1";

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: ROOT,
    encoding: "utf8",
    shell: false,
    windowsHide: true,
    maxBuffer: 16 * 1024 * 1024,
    ...options,
  });
  if (result.error && result.error.code === "ENOENT") return { missing: true };
  if (result.status !== 0) {
    errors.push(
      `${command} ${args.join(" ")} failed:\n` +
      `${(result.stderr || result.stdout || result.error?.message || "").trim()}`,
    );
  }
  return result;
}

function unavailable(label) {
  const message = `${label} unavailable; its examples were not validated by the native tool.`;
  if (requireToolchains) errors.push(message);
  else notes.push(message);
}

for (const file of allRepositoryFiles((candidate) => /\.(json|ya?ml)$/i.test(candidate))) {
  const rel = relative(file);
  if (rel === "package-lock.json") continue;
  try {
    const source = fs.readFileSync(file, "utf8");
    if (file.endsWith(".json")) JSON.parse(source);
    else YAML.parse(source, { uniqueKeys: true, logLevel: "silent" });
  } catch (error) {
    errors.push(`${rel}: ${error.message}`);
  }
}

for (const file of allRepositoryFiles((candidate) => candidate.endsWith(".js"))) {
  if (!relative(file).startsWith("node_modules/")) run(process.execPath, ["--check", file]);
}

const goFiles = allRepositoryFiles((candidate) => candidate.endsWith(".go"));
if (goFiles.length) {
  const go = process.platform === "win32" ? "go.exe" : "go";
  const version = run(go, ["version"]);
  if (version.missing) {
    unavailable("Go toolchain");
  } else {
    const gofmt = process.platform === "win32" ? "gofmt.exe" : "gofmt";
    const format = run(gofmt, ["-l", ...goFiles]);
    if (!format.missing && format.status === 0 && format.stdout.trim()) {
      errors.push(`Go files are not gofmt-clean:\n${format.stdout.trim()}`);
    }
    const outputDirectory = fs.mkdtempSync(
      path.join(os.tmpdir(), "security-writeups-go-"),
    );
    try {
      for (const file of goFiles) {
        const digest = crypto
          .createHash("sha256")
          .update(relative(file))
          .digest("hex")
          .slice(0, 12);
        const suffix = process.platform === "win32" ? ".exe" : "";
        run(go, [
          "build",
          "-trimpath",
          "-o",
          path.join(outputDirectory, `${digest}${suffix}`),
          file,
        ]);
      }
      run(go, ["run", path.join("appsec", "scripts", "oauth-pkce-verifier.go")]);
    } finally {
      fs.rmSync(outputDirectory, { recursive: true, force: true });
    }
  }
}

const terraformFiles = allRepositoryFiles((candidate) => candidate.endsWith(".tf"));
if (terraformFiles.length) {
  const terraform = process.platform === "win32" ? "terraform.exe" : "terraform";
  const version = run(terraform, ["version"]);
  if (version.missing) {
    unavailable("Terraform CLI");
  } else {
    for (const file of terraformFiles) {
      run(terraform, ["fmt", "-check", file]);
    }
    for (const directory of [
      path.join(ROOT, "labs", "iac-policy", "terraform", "hardened"),
      path.join(ROOT, "labs", "iac-policy", "terraform", "insecure"),
    ]) {
      run(
        terraform,
        ["init", "-backend=false", "-input=false", "-no-color"],
        { cwd: directory },
      );
      run(terraform, ["validate", "-no-color"], { cwd: directory });
    }
  }
}

const bicepFiles = allRepositoryFiles((candidate) => candidate.endsWith(".bicep"));
if (bicepFiles.length) {
  const bicepPath = path.join("labs", "azure-landing-zone", "main.bicep");
  const result = process.platform === "win32"
    ? run(process.env.ComSpec || "cmd.exe", [
      "/d",
      "/s",
      "/c",
      `az bicep build --file ${bicepPath} --stdout`,
    ])
    : run("az", ["bicep", "build", "--file", bicepPath, "--stdout"]);
  if (result.missing) notes.push("Azure CLI unavailable; Bicep compilation was not validated.");
}

const shellFiles = allRepositoryFiles((candidate) => candidate.endsWith(".sh"));
if (shellFiles.length) {
  const result = run(
    process.platform === "win32" ? "shellcheck.exe" : "shellcheck",
    shellFiles.map(relative),
  );
  if (result.missing) {
    if (requireToolchains) errors.push("ShellCheck unavailable; shell validation is required in CI.");
    else notes.push("ShellCheck unavailable; shell scripts require the documented lab runtime check.");
  }
}

const powershellFiles = allRepositoryFiles((candidate) => candidate.endsWith(".ps1"));
if (powershellFiles.length) {
  const executable = process.platform === "win32" ? "powershell.exe" : "pwsh";
  const result = run(executable, [
    "-NoProfile",
    "-NonInteractive",
    "-File",
    path.join("scripts", "validate-powershell.ps1"),
  ]);
  if (result.missing) notes.push("PowerShell unavailable; PowerShell syntax was not validated.");
}

for (const note of notes) console.warn(`Validation limitation: ${note}`);
if (errors.length) {
  console.error(`Code/configuration validation failed with ${errors.length} error(s):`);
  for (const item of errors) console.error(`- ${item}`);
  process.exit(1);
}
console.log(
  `Code/configuration validation passed for JSON/YAML, JavaScript, ${goFiles.length} Go file(s), ` +
  `${terraformFiles.length} Terraform file(s), and available platform tools.`,
);
