"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const YAML = require("yaml");
const { ROOT, allRepositoryFiles, relative } = require("./content-lib");
const errors = [];
const notes = [];

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { cwd: ROOT, encoding: "utf8", shell: false, maxBuffer: 16 * 1024 * 1024, ...options });
  if (result.error && result.error.code === "ENOENT") return { missing: true };
  if (result.status !== 0) errors.push(`${command} ${args.join(" ")} failed:\n${(result.stderr || result.stdout || result.error?.message || "").trim()}`);
  return result;
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

const terraformFiles = allRepositoryFiles((candidate) => candidate.endsWith(".tf"));
if (terraformFiles.length) {
  const result = run(process.platform === "win32" ? "terraform.exe" : "terraform", ["fmt", "-check", "-recursive", "labs"]);
  if (result.missing) notes.push("Terraform CLI unavailable; Terraform formatting was not validated.");
}
const bicepFiles = allRepositoryFiles((candidate) => candidate.endsWith(".bicep"));
if (bicepFiles.length) {
  const bicepPath = path.join("labs", "azure-landing-zone", "main.bicep");
  const result = process.platform === "win32"
    ? run(process.env.ComSpec || "cmd.exe", [
      "/d", "/s", "/c",
      `az bicep build --file ${bicepPath} --stdout`,
    ])
    : run("az", ["bicep", "build", "--file", bicepPath, "--stdout"]);
  if (result.missing) notes.push("Azure CLI unavailable; Bicep compilation was not validated.");
}
const shellFiles = allRepositoryFiles((candidate) => candidate.endsWith(".sh"));
if (shellFiles.length) {
  const result = run(process.platform === "win32" ? "shellcheck.exe" : "shellcheck", shellFiles.map(relative));
  if (result.missing) notes.push("ShellCheck unavailable; shell scripts require the documented lab runtime check.");
}
const powershellFiles = allRepositoryFiles((candidate) => candidate.endsWith(".ps1"));
if (powershellFiles.length) {
  const executable = process.platform === "win32" ? "powershell.exe" : "pwsh";
  const result = run(executable, ["-NoProfile", "-NonInteractive", "-File", path.join("scripts", "validate-powershell.ps1")]);
  if (result.missing) notes.push("PowerShell unavailable; PowerShell syntax was not validated.");
}

for (const note of notes) console.warn(`Validation limitation: ${note}`);
if (errors.length) {
  console.error(`Code/configuration validation failed with ${errors.length} error(s):`);
  for (const item of errors) console.error(`- ${item}`);
  process.exit(1);
}
console.log("Code/configuration syntax and available tool checks passed.");
