import {execFileSync} from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function git(args) {
  return execFileSync("git", args, {cwd: root, encoding: "utf8"}).trim();
}

function nonQaDirty(porcelain) {
  return porcelain
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .filter((line) => {
      const pathPart = line.replace(/^[A-Z?]{1,2}\s+/, "").replace(/^"/, "").replace(/"$/, "");
      return !pathPart.startsWith("qa/") && !pathPart.startsWith("qa-artifacts/");
    })
    .join("\n");
}

/**
 * Build provenance for a runtime QA report that validates a checked-out revision.
 * Reports are Actions artifacts; they must not claim to be committed inside the
 * revision under test.
 */
export function buildProvenance({
  command,
  toolVersions = {},
  result = "passed",
  extra = {}
} = {}) {
  let sourceCommit;
  let sourceTree;
  let dirty;
  try {
    sourceCommit = git(["rev-parse", "HEAD"]);
    sourceTree = git(["rev-parse", "HEAD^{tree}"]);
    dirty = nonQaDirty(git(["status", "--porcelain"]));
  } catch (error) {
    throw new Error(`Git provenance unavailable: ${error.message}`);
  }
  if (!sourceCommit || !sourceTree) {
    throw new Error("Unable to determine validated commit or tree SHA.");
  }
  if (dirty && process.env.QA_ALLOW_DIRTY !== "1") {
    throw new Error(
      "Working tree is dirty outside qa/; commit or stash before generating reports (or set QA_ALLOW_DIRTY=1 for local iteration)."
    );
  }

  const eventName = process.env.GITHUB_EVENT_NAME || "local";
  const ref = process.env.GITHUB_REF || git(["rev-parse", "--abbrev-ref", "HEAD"]) || "detached";
  const report = {
    executedAt: new Date().toISOString(),
    sourceCommit,
    sourceTree,
    validatedCommit: sourceCommit,
    validatedTree: sourceTree,
    repository: "jasonachkar/cybersecurity-writeups",
    eventName,
    ref,
    workflowRunId: process.env.GITHUB_RUN_ID || null,
    workflowRunAttempt: process.env.GITHUB_RUN_ATTEMPT
      ? Number(process.env.GITHUB_RUN_ATTEMPT)
      : null,
    dirtyWorkingTree: Boolean(dirty),
    command: command || process.env.npm_lifecycle_event || "unknown",
    toolVersions,
    result,
    ...extra
  };

  if (eventName === "pull_request") {
    report.pullRequestHeadCommit = process.env.GITHUB_PR_HEAD_SHA || null;
    report.pullRequestBaseCommit = process.env.GITHUB_PR_BASE_SHA || null;
  }

  return report;
}

export function writeQaReport(filename, body) {
  const target = path.join(root, "qa", filename);
  fs.mkdirSync(path.dirname(target), {recursive: true});
  fs.writeFileSync(target, `${JSON.stringify(body, null, 2)}\n`);
  return target;
}

export function requireField(report, field) {
  if (report[field] === undefined || report[field] === null || report[field] === "") {
    throw new Error(`${field} is required in QA report`);
  }
}

export {root};
