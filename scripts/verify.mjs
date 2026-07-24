#!/usr/bin/env node
/**
 * Orchestrate verification suites and stamp qa/* reports with provenance.
 *
 * Suites (argv[2]): static | labs | node | go | terraform | opa | bicep |
 *   policy-schemas | postgres | shell | powershell | secrets | a11y | links | all
 */
import {spawnSync} from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import {createRequire} from "node:module";
import {buildProvenance, writeQaReport, root} from "./qa-provenance.mjs";
import {fetchPinnedTool} from "./fetch-pinned-tool.mjs";
import {
  TERRAFORM_VERSION,
  TETRAGON_CRD,
  KYVERNO_IVP_CRD,
  OPA_VERSION,
  KYVERNO_CLI_VERSION,
  KYVERNO_CLI_ARTIFACTS,
  GITLEAKS_VERSION,
  BICEP_VERSION
} from "./tool-pins.mjs";

const require = createRequire(import.meta.url);
const isWin = process.platform === "win32";

function fail(message, code = 1) {
  console.error(message);
  process.exit(code);
}

function missingTool(name, installHint) {
  fail(
    `Required tool missing: ${name}\n` +
      `Install it, then re-run the suite.\n` +
      `Hint: ${installHint}`
  );
}

/**
 * @param {string} command
 * @param {string[]} args
 * @param {{cwd?: string, shell?: boolean, env?: NodeJS.ProcessEnv, inherit?: boolean, input?: string}} [options]
 */
function runCapture(command, args, options = {}) {
  const shell = options.shell ?? false;
  console.log(`\n→ ${command} ${args.join(" ")}`);
  const result = spawnSync(command, args, {
    cwd: options.cwd || root,
    encoding: "utf8",
    shell,
    env: options.env || process.env,
    input: options.input,
    stdio: options.inherit ? "inherit" : undefined,
    maxBuffer: 32 * 1024 * 1024
  });
  return result;
}

function run(command, args, options = {}) {
  const result = options.inherit === false
    ? runCapture(command, args, options)
    : (() => {
        const shell = options.shell ?? false;
        console.log(`\n→ ${command} ${args.join(" ")}`);
        return spawnSync(command, args, {
          cwd: options.cwd || root,
          stdio: "inherit",
          shell,
          env: options.env || process.env
        });
      })();
  if (result.error && result.error.code === "ENOENT") {
    missingTool(command, options.installHint || `install ${command}`);
  }
  if (result.status !== 0) {
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
    process.exit(result.status ?? 1);
  }
  return result;
}

function toolVersion(command, versionArgs = ["--version"], options = {}) {
  const result = spawnSync(command, versionArgs, {
    cwd: root,
    encoding: "utf8",
    shell: options.shell ?? false,
    env: process.env
  });
  if (result.error?.code === "ENOENT" || result.status !== 0) {
    missingTool(command, options.installHint || `install ${command}`);
  }
  return (result.stdout || result.stderr || "").trim().split(/\r?\n/)[0];
}

function stamp(filename, {command, toolVersions = {}, result = "passed", extra = {}}) {
  const body = buildProvenance({command, toolVersions, result, extra});
  const target = writeQaReport(filename, body);
  console.log(`Wrote ${path.relative(root, target)}`);
  return body;
}

function mergeStamp(filename, {command, toolVersions = {}, result = "passed", extra = {}}) {
  const target = path.join(root, "qa", filename);
  let existing = {};
  if (fs.existsSync(target)) {
    try {
      existing = JSON.parse(fs.readFileSync(target, "utf8"));
    } catch {
      existing = {};
    }
  }
  const provenance = buildProvenance({command, toolVersions, result, extra});
  const body = {...existing, ...provenance, ...extra};
  writeQaReport(filename, body);
  console.log(`Stamped ${filename}`);
  return body;
}

function listFiles(dir, predicate) {
  const out = [];
  if (!fs.existsSync(dir)) return out;
  for (const item of fs.readdirSync(dir, {withFileTypes: true})) {
    const full = path.join(dir, item.name);
    if (item.isDirectory()) {
      if (item.name === "node_modules" || item.name === ".git") continue;
      out.push(...listFiles(full, predicate));
    } else if (item.isFile() && predicate(full)) {
      out.push(full);
    }
  }
  return out;
}

function pythonBin(venvDir) {
  return isWin
    ? path.join(venvDir, "Scripts", "python.exe")
    : path.join(venvDir, "bin", "python");
}

function ensurePolicyVenv() {
  const venvDir = path.join(root, "qa-artifacts", "policy-venv");
  const py = pythonBin(venvDir);
  const requirements = path.join(root, "scripts", "requirements-policy.txt");
  if (!fs.existsSync(py)) {
    const create = spawnSync("python", ["-m", "venv", venvDir], {
      cwd: root,
      encoding: "utf8",
      shell: false
    });
    if (create.status !== 0) {
      const create3 = spawnSync("python3", ["-m", "venv", venvDir], {
        cwd: root,
        encoding: "utf8",
        shell: false
      });
      if (create3.status !== 0) {
        fail(
          "Python venv creation failed. Install Python 3 and re-run.\n" +
            `${create.stderr || ""}\n${create3.stderr || ""}`
        );
      }
    }
  }
  const probe = spawnSync(py, ["-c", "import yaml, jsonschema"], {
    cwd: root,
    encoding: "utf8",
    shell: false
  });
  if (probe.status !== 0) {
    run(py, ["-m", "pip", "install", "--disable-pip-version-check", "-r", requirements], {
      installHint: "ensure Python pip works inside the created venv"
    });
  }
  return py;
}

async function suiteStatic() {
  run(process.execPath, ["scripts/validate-gh-pages.mjs"]);
  run(process.execPath, ["scripts/run-html-validation.mjs"]);
  run(process.execPath, ["scripts/check-known-defects.mjs"]);

  const htmlValidate = JSON.parse(fs.readFileSync(require.resolve("html-validate/package.json"), "utf8"));
  const toolVersions = {node: process.version, htmlValidate: htmlValidate.version};
  mergeStamp("validation-report.json", {
    command: "npm run verify:static",
    toolVersions,
    result: "passed",
    extra: {detailSource: "validation-report.json"}
  });
  mergeStamp("html-validation-report.json", {
    command: "npm run verify:static",
    toolVersions,
    result: "passed",
    extra: {detailSource: "html-validation-report.json"}
  });
  stamp("defect-check-report.json", {
    command: "npm run verify:static",
    toolVersions,
    result: "passed",
    extra: {patternsChecked: 21}
  });
}

async function suiteLabs() {
  const tests = [
    ["--test", "labs/ai-agent-security/tests/broker.test.js"],
    ["--test", "labs/oauth-oidc/tests/oauth-security.test.js"],
    ["--test", "labs/secure-cicd/tests/policy-tests.js"],
    ["labs/secure-cicd/tests/run-tests.js"],
    ["--test", "labs/kubernetes-security/tests/run-tests.js"],
    ["--test", "labs/supply-chain/tests/run-tests.js"],
    ["labs/iam-oidc/tests/run-tests.js"],
    ["labs/iac-policy/tests/run-tests.js"]
  ];
  for (const args of tests) {
    run(process.execPath, args);
  }
  stamp("labs-report.json", {
    command: "npm run verify:node",
    toolVersions: {node: process.version},
    result: "passed",
    extra: {
      suites: [
        "ai-agent-security",
        "oauth-oidc",
        "secure-cicd",
        "kubernetes-security",
        "supply-chain",
        "iam-oidc",
        "iac-policy"
      ]
    }
  });
}

async function suiteGo() {
  const goVersion = toolVersion("go", ["version"], {
    installHint: "https://go.dev/dl/ — install Go and ensure go is on PATH"
  });
  const modules = [
    "appsec/scripts/oauth-pkce",
    "threat-intel/scripts/cloudtrail",
    "cloud-security/scripts/k8s-rbac"
  ];
  const moduleResults = [];
  for (const mod of modules) {
    const cwd = path.join(root, mod);
    if (!fs.existsSync(cwd)) fail(`Go module directory missing: ${mod}`);

    // gofmt -d does not fail on diffs; treat any stdout as failure. Never use -w.
    const fmt = runCapture("gofmt", ["-d", "."], {cwd});
    if (fmt.error?.code === "ENOENT") {
      missingTool("gofmt", "install Go (gofmt ships with the toolchain)");
    }
    if (fmt.status !== 0) {
      process.stderr.write(fmt.stderr || fmt.stdout || "");
      process.exit(fmt.status ?? 1);
    }
    if ((fmt.stdout || "").trim()) {
      console.error(`gofmt -d reported formatting diffs in ${mod}:`);
      process.stdout.write(fmt.stdout);
      process.exit(1);
    }

    run("go", ["test", "./..."], {cwd, installHint: "install Go from https://go.dev/dl/"});
    run("go", ["vet", "./..."], {cwd, installHint: "install Go from https://go.dev/dl/"});
    moduleResults.push({module: mod, gofmt: "clean", test: "passed", vet: "passed"});
  }
  stamp("go-report.json", {
    command: "npm run verify:go",
    toolVersions: {go: goVersion},
    result: "passed",
    extra: {modules: moduleResults}
  });
}

async function suiteTerraform() {
  const tfVersionLine = toolVersion("terraform", ["version"], {
    installHint: `install Terraform ${TERRAFORM_VERSION} from https://developer.hashicorp.com/terraform/install`
  });
  if (!tfVersionLine.includes(TERRAFORM_VERSION)) {
    fail(
      `Terraform ${TERRAFORM_VERSION} required; found: ${tfVersionLine}\n` +
        `Install the pinned version and re-run.`
    );
  }
  const tfDirs = [
    "labs/iac-policy/terraform/hardened",
    "labs/iac-policy/terraform/insecure"
  ];
  const results = [];
  for (const dir of tfDirs) {
    const cwd = path.join(root, dir);
    if (!fs.existsSync(cwd)) fail(`Terraform directory missing: ${dir}`);
    run("terraform", ["fmt", "-check", "-recursive"], {cwd});
    run("terraform", ["init", "-backend=false", "-input=false"], {cwd});
    run("terraform", ["validate"], {cwd});
    results.push({directory: dir, fmt: "passed", init: "passed", validate: "passed"});
  }
  stamp("terraform-report.json", {
    command: "npm run verify:terraform",
    toolVersions: {terraform: tfVersionLine},
    result: "passed",
    extra: {directories: results, expectedVersion: TERRAFORM_VERSION}
  });
}

async function suiteOpa() {
  const opaVersion = toolVersion("opa", ["version"], {
    installHint: `install OPA ${OPA_VERSION} from https://www.openpolicyagent.org/docs/latest/#running-opa`
  });
  run("opa", ["test", "labs/iac-policy/policy", "-v"], {
    installHint: `install OPA ${OPA_VERSION}`
  });
  stamp("opa-report.json", {
    command: "npm run verify:opa",
    toolVersions: {opa: opaVersion},
    result: "passed",
    extra: {policyDir: "labs/iac-policy/policy", expectedVersion: OPA_VERSION}
  });
}

async function suiteBicep() {
  // Prefer standalone pinned Bicep CLI; fall back to `az bicep` when available.
  let bicepCmd = null;
  let toolVersions = {};

  const probeBicep = spawnSync("bicep", ["--version"], {cwd: root, encoding: "utf8", shell: isWin});
  if (!probeBicep.error && probeBicep.status === 0) {
    bicepCmd = {command: isWin ? "bicep.cmd" : "bicep", argsPrefix: []};
    toolVersions.bicep = (probeBicep.stdout || probeBicep.stderr || "").trim().split(/\r?\n/)[0];
  } else {
    const azCmd = isWin ? "az.cmd" : "az";
    const azProbe = spawnSync(azCmd, ["bicep", "version"], {
      cwd: root,
      encoding: "utf8",
      shell: isWin
    });
    if (!azProbe.error && azProbe.status === 0) {
      bicepCmd = {command: azCmd, argsPrefix: ["bicep"], shell: isWin};
      toolVersions.azureCliBicep = (azProbe.stdout || azProbe.stderr || "").trim().split(/\r?\n/)[0];
    }
  }

  if (!bicepCmd) {
    missingTool(
      "bicep",
      `install standalone Bicep ${BICEP_VERSION} or Azure CLI with bicep`
    );
  }

  const outfile = path.join(root, "labs/azure-landing-zone/main.json");
  try {
    if (bicepCmd.argsPrefix.length) {
      run(
        bicepCmd.command,
        [
          ...bicepCmd.argsPrefix,
          "build",
          "--file",
          "labs/azure-landing-zone/main.bicep",
          "--outfile",
          "labs/azure-landing-zone/main.json"
        ],
        {shell: Boolean(bicepCmd.shell), installHint: "install Bicep or Azure CLI bicep"}
      );
    } else {
      run(
        bicepCmd.command,
        [
          "build",
          "labs/azure-landing-zone/main.bicep",
          "--outfile",
          "labs/azure-landing-zone/main.json"
        ],
        {shell: Boolean(bicepCmd.shell), installHint: "install standalone Bicep"}
      );
    }
  } finally {
    if (fs.existsSync(outfile)) fs.unlinkSync(outfile);
  }

  stamp("bicep-report.json", {
    command: "npm run verify:bicep",
    toolVersions,
    result: "passed",
    extra: {
      file: "labs/azure-landing-zone/main.bicep",
      compiledArtifactDeleted: true,
      expectedStandaloneVersion: BICEP_VERSION
    }
  });
}

async function suiteKyverno() {
  const platform =
    process.platform === "win32"
      ? "windows-amd64"
      : process.platform === "darwin"
        ? process.arch === "arm64"
          ? "darwin-arm64"
          : "darwin-amd64"
        : process.arch === "arm64"
          ? "linux-arm64"
          : "linux-amd64";
  const artifact = KYVERNO_CLI_ARTIFACTS[platform];
  if (!artifact) fail(`No Kyverno CLI pin for platform ${platform}`);

  const archivePath = path.join(root, "qa-artifacts", "tools", path.basename(artifact.url));
  await fetchPinnedTool({
    url: artifact.url,
    sha256: artifact.sha256,
    destPath: archivePath
  });

  const extractDir = path.join(root, "qa-artifacts", "tools", `kyverno-${KYVERNO_CLI_VERSION}`);
  fs.mkdirSync(extractDir, {recursive: true});
  const kyvernoBin = path.join(
    extractDir,
    process.platform === "win32" ? "kyverno.exe" : "kyverno"
  );
  if (!fs.existsSync(kyvernoBin)) {
    if (archivePath.endsWith(".zip")) {
      if (isWin) {
        run("powershell.exe", [
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          `Expand-Archive -LiteralPath '${archivePath.replace(/'/g, "''")}' -DestinationPath '${extractDir.replace(/'/g, "''")}' -Force`
        ]);
      } else {
        run("unzip", ["-o", archivePath, "-d", extractDir]);
      }
    } else {
      run("tar", ["-xzf", archivePath, "-C", extractDir]);
    }
  }
  if (!fs.existsSync(kyvernoBin)) {
    // Some archives nest the binary; search one level.
    const found = listFiles(extractDir, (file) => /kyverno(\.exe)?$/i.test(path.basename(file)));
    if (!found.length) fail(`Kyverno binary missing after extract in ${extractDir}`);
    fs.copyFileSync(found[0], kyvernoBin);
    if (!isWin) fs.chmodSync(kyvernoBin, 0o755);
  } else if (!isWin) {
    try {
      fs.chmodSync(kyvernoBin, 0o755);
    } catch {
      /* ignore */
    }
  }

  const versionLine = toolVersion(kyvernoBin, ["version"], {
    installHint: `install Kyverno CLI ${KYVERNO_CLI_VERSION}`
  });
  run(kyvernoBin, ["test", "labs/kubernetes-security", "--remove-color"], {
    installHint: `install Kyverno CLI ${KYVERNO_CLI_VERSION}`
  });

  stamp("kyverno-report.json", {
    command: "npm run verify:kyverno",
    toolVersions: {kyvernoCli: versionLine, expected: KYVERNO_CLI_VERSION},
    result: "passed",
    extra: {
      suite: "hardened-pod-native-test",
      note: "Image-signature / ImageValidatingPolicy remains schema-only; not covered by this native test."
    }
  });
}

async function suitePolicySchemas() {
  const python = ensurePolicyVenv();
  const crdDir = path.join(root, "qa-artifacts", "crds");
  const tetragonCrdPath = path.join(crdDir, `tetragon-tracingpoliciesnamespaced-v${TETRAGON_CRD.version}.yaml`);
  const kyvernoCrdPath = path.join(crdDir, `kyverno-imagevalidatingpolicies-v${KYVERNO_IVP_CRD.version}.yaml`);

  await fetchPinnedTool({
    url: TETRAGON_CRD.url,
    sha256: TETRAGON_CRD.sha256,
    destPath: tetragonCrdPath
  });
  await fetchPinnedTool({
    url: KYVERNO_IVP_CRD.url,
    sha256: KYVERNO_IVP_CRD.sha256,
    destPath: kyvernoCrdPath
  });

  run(python, [
    "scripts/validate-tetragon-policy.py",
    tetragonCrdPath,
    TETRAGON_CRD.policyPath
  ]);
  run(python, [
    "scripts/validate-kyverno-policy.py",
    kyvernoCrdPath,
    KYVERNO_IVP_CRD.policyPath
  ]);

  const pythonVersion = (runCapture(python, ["--version"]).stdout || "").trim();
  stamp("policy-schemas-report.json", {
    command: "npm run verify:policy-schemas",
    toolVersions: {
      python: pythonVersion,
      tetragonCrd: TETRAGON_CRD.version,
      kyvernoIvpCrd: KYVERNO_IVP_CRD.version
    },
    result: "passed",
    extra: {
      tetragon: {
        crdUrl: TETRAGON_CRD.url,
        crdSha256: TETRAGON_CRD.sha256,
        policy: TETRAGON_CRD.policyPath,
        mode: "schema-only"
      },
      kyverno: {
        crdUrl: KYVERNO_IVP_CRD.url,
        crdSha256: KYVERNO_IVP_CRD.sha256,
        policy: KYVERNO_IVP_CRD.policyPath,
        mode: "schema-only"
      }
    }
  });
}

async function suitePostgres() {
  const script = "labs/postgresql-rls/run-tests.sh";
  if (!fs.existsSync(path.join(root, script))) fail(`Missing ${script}`);
  run("bash", [script], {
    shell: isWin,
    installHint: "install Git Bash or WSL bash, plus Docker for the compose stack"
  });
  stamp("postgres-report.json", {
    command: "npm run verify:postgresql",
    toolVersions: {bash: "bash", node: process.version},
    result: "passed",
    extra: {script}
  });
}

async function suiteShell() {
  const shellcheckVersion = toolVersion("shellcheck", ["--version"], {
    installHint: "install shellcheck (https://www.shellcheck.net/) and ensure it is on PATH"
  });
  const scripts = listFiles(path.join(root, "labs"), (file) => file.endsWith(".sh"))
    .map((file) => path.relative(root, file).split(path.sep).join("/"))
    .sort();
  if (!scripts.length) fail("No .sh files found under labs/");
  for (const script of scripts) {
    run("shellcheck", [script], {
      installHint: "install shellcheck"
    });
  }
  stamp("shell-report.json", {
    command: "npm run verify:shell",
    toolVersions: {shellcheck: shellcheckVersion},
    result: "passed",
    extra: {scripts}
  });
}

async function suitePowershell() {
  const scriptRel = "labs/postgresql-rls/run-tests.ps1";
  const scriptPath = path.join(root, scriptRel);
  if (!fs.existsSync(scriptPath)) fail(`Missing ${scriptRel}`);

  const pwsh = isWin ? "powershell.exe" : "pwsh";
  const parseCmd = `
$ErrorActionPreference = 'Stop'
$path = '${scriptPath.replace(/'/g, "''")}'
$tokens = $null
$errors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
if ($errors -and $errors.Count -gt 0) {
  $errors | ForEach-Object { Write-Error $_.ToString() }
  exit 1
}
Write-Output 'parse-ok'
`;
  const result = runCapture(pwsh, ["-NoProfile", "-NonInteractive", "-Command", parseCmd], {
    shell: false
  });
  if (result.error?.code === "ENOENT") {
    missingTool(
      pwsh,
      isWin
        ? "Windows PowerShell should be available; install PowerShell 7 if needed"
        : "install PowerShell 7 (pwsh) from https://aka.ms/powershell"
    );
  }
  if (result.status !== 0 || !(result.stdout || "").includes("parse-ok")) {
    process.stderr.write(result.stderr || result.stdout || "PowerShell parse failed\n");
    process.exit(result.status ?? 1);
  }

  stamp("powershell-report.json", {
    command: "npm run verify:powershell",
    toolVersions: {powershell: pwsh},
    result: "passed",
    extra: {
      script: scriptRel,
      mode: "syntax-parse-only",
      note: "Parser AST check only; the script was not executed."
    }
  });
}

function readGitleaksFindings(reportPath) {
  if (!fs.existsSync(reportPath)) return [];
  const raw = JSON.parse(fs.readFileSync(reportPath, "utf8"));
  if (Array.isArray(raw)) return raw;
  if (Array.isArray(raw.findings)) return raw.findings;
  return [];
}

async function suiteSecrets() {
  const gitleaksVersion = toolVersion("gitleaks", ["version"], {
    installHint: `install Gitleaks ${GITLEAKS_VERSION} from https://github.com/gitleaks/gitleaks/releases`
  });
  fs.mkdirSync(path.join(root, "qa"), {recursive: true});
  const dirReport = path.join(root, "qa-artifacts", "gitleaks-dir.json");
  const gitReport = path.join(root, "qa-artifacts", "gitleaks-git.json");
  fs.mkdirSync(path.dirname(dirReport), {recursive: true});
  const configArgs = fs.existsSync(path.join(root, ".gitleaks.toml"))
    ? ["--config", ".gitleaks.toml"]
    : [];

  const dirScan = spawnSync(
    "gitleaks",
    ["dir", ".", "--redact", ...configArgs, "--report-path", dirReport, "--report-format", "json"],
    {cwd: root, encoding: "utf8", shell: false, stdio: "inherit"}
  );
  if (dirScan.error?.code === "ENOENT") {
    missingTool("gitleaks", `install Gitleaks ${GITLEAKS_VERSION}`);
  }

  const gitScan = spawnSync(
    "gitleaks",
    ["git", ".", "--redact", ...configArgs, "--report-path", gitReport, "--report-format", "json"],
    {cwd: root, encoding: "utf8", shell: false, stdio: "inherit"}
  );

  const workingTreeFindings = readGitleaksFindings(dirReport);
  const historyFindings = readGitleaksFindings(gitReport);
  const workingTreeFindingCount = workingTreeFindings.length;
  const historyFindingCount = historyFindings.length;
  const passed =
    dirScan.status === 0 &&
    gitScan.status === 0 &&
    workingTreeFindingCount === 0 &&
    historyFindingCount === 0;

  stamp("gitleaks-report.json", {
    command: "npm run verify:secrets",
    toolVersions: {gitleaks: gitleaksVersion, expected: GITLEAKS_VERSION},
    result: passed ? "passed" : "failed",
    extra: {
      scanScopes: ["working-tree", "git-history"],
      workingTreeFindingCount,
      historyFindingCount,
      findingCount: workingTreeFindingCount + historyFindingCount,
      workingTreeFindings,
      historyFindings
    }
  });
  if (!passed) process.exit(1);
}

async function suiteA11y() {
  run(process.execPath, ["scripts/run-accessibility-audit.mjs"]);
}

async function suiteLinks() {
  run(process.execPath, ["scripts/check-external-links.mjs"]);
  const target = path.join(root, "qa", "external-link-report.json");
  const existing = JSON.parse(fs.readFileSync(target, "utf8"));
  const result = existing.counts?.broken ? "failed" : "passed";
  mergeStamp("external-link-report.json", {
    command: "npm run verify:links",
    toolVersions: {node: process.version},
    result,
    extra: {}
  });
  if (result !== "passed") process.exit(1);
}

async function suiteSummaryAndProvenance() {
  run(process.execPath, ["scripts/stamp-qa-reports.mjs", "summary"]);
  run(process.execPath, ["scripts/verify-qa-provenance.mjs"]);
}

const suite = process.argv[2] || "all";
const handlers = {
  static: suiteStatic,
  labs: suiteLabs,
  node: suiteLabs,
  go: suiteGo,
  terraform: suiteTerraform,
  opa: suiteOpa,
  bicep: suiteBicep,
  "policy-schemas": suitePolicySchemas,
  kyverno: suiteKyverno,
  postgres: suitePostgres,
  shell: suiteShell,
  powershell: suitePowershell,
  secrets: suiteSecrets,
  a11y: suiteA11y,
  links: suiteLinks
};

const allOrder = [
  "static",
  "labs",
  "go",
  "terraform",
  "opa",
  "bicep",
  "policy-schemas",
  "kyverno",
  "postgres",
  "shell",
  "powershell",
  "a11y",
  "links",
  "secrets"
];

async function main() {
  if (suite === "all") {
    for (const name of allOrder) {
      console.log(`\n======== verify:${name} ========`);
      await handlers[name]();
    }
    console.log("\n======== verify:summary + provenance ========");
    await suiteSummaryAndProvenance();
    console.log("\nverify:all completed successfully.");
    return;
  }

  const handler = handlers[suite];
  if (!handler) {
    fail(`Unknown suite: ${suite}\nKnown: ${Object.keys(handlers).concat(["all"]).join(", ")}`, 2);
  }
  await handler();
  console.log(`\nverify:${suite} completed successfully.`);
}

main().catch((error) => {
  console.error(error.stack || error.message || error);
  process.exit(1);
});
