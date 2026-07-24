import {execFileSync} from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function git(args) {
  return execFileSync("git", args, {cwd: root, encoding: "utf8"}).trim();
}

export function requireCleanProvenance({command, toolVersions = {}, result = "passed"} = {}) {
  let gitCommit;
  let gitTree;
  let branch;
  let dirty;
  try {
    gitCommit = git(["rev-parse", "HEAD"]);
    gitTree = git(["rev-parse", "HEAD^{tree}"]);
    branch = git(["branch", "--show-current"]) || process.env.GITHUB_REF_NAME || "detached";
    dirty = git(["status", "--porcelain"])
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .filter((line) => {
        // Report generators and CI artifact assembly write under qa/ and
        // qa-artifacts/; that must not invalidate provenance for source.
        const pathPart = line.replace(/^[A-Z?]{1,2}\s+/, "").replace(/^"/, "").replace(/"$/, "");
        return !pathPart.startsWith("qa/") && !pathPart.startsWith("qa-artifacts/");
      })
      .join("\n");
  } catch (error) {
    throw new Error(`Git provenance unavailable: ${error.message}`);
  }
  if (dirty) {
    if (process.env.QA_ALLOW_DIRTY === "1") {
      return {
        executedAt: new Date().toISOString(),
        gitCommit,
        gitTree,
        repository: "jasonachkar/cybersecurity-writeups",
        branch,
        dirtyWorkingTree: true,
        command: command || process.env.npm_lifecycle_event || "unknown",
        toolVersions,
        result
      };
    }
    throw new Error("Working tree is dirty; commit or stash changes before generating QA reports (or set QA_ALLOW_DIRTY=1 for local iteration).");
  }
  if (!gitCommit || !gitTree) {
    throw new Error("Unable to determine git commit or tree SHA.");
  }
  return {
    executedAt: new Date().toISOString(),
    gitCommit,
    gitTree,
    repository: "jasonachkar/cybersecurity-writeups",
    branch,
    dirtyWorkingTree: false,
    command: command || process.env.npm_lifecycle_event || "unknown",
    toolVersions,
    result
  };
}

export function writeQaReport(filename, body) {
  const target = path.join(root, "qa", filename);
  fs.mkdirSync(path.dirname(target), {recursive: true});
  fs.writeFileSync(target, `${JSON.stringify(body, null, 2)}\n`);
  return target;
}

export {root};
