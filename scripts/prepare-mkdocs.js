"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");
const PROJECT = path.join(ROOT, "mkdocs-project");
const STAGING = path.join(PROJECT, "generated-docs");
const GENERATED_FOOTER = path.join(
  PROJECT,
  "overrides",
  "partials",
  "deployment-meta.generated.html",
);
const REPOSITORY = "jasonachkar/cybersecurity-writeups";
const REPOSITORY_URL = `https://github.com/${REPOSITORY}`;
const SITE_URL = "https://docs.jasonachkardiab.com";
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const BRANCH_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$/;
const UTC_TIMESTAMP_PATTERN =
  /^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\dZ$/;

function fail(message) {
  throw new Error(message);
}

function git(...args) {
  const result = spawnSync("git", args, {
    cwd: ROOT,
    encoding: "utf8",
    windowsHide: true,
  });
  if (result.status !== 0) {
    fail(`git ${args.join(" ")} failed: ${(result.stderr || result.stdout).trim()}`);
  }
  return result.stdout.trim();
}

function utcNowToSeconds() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

function assertCleanWorktree() {
  const status = git("status", "--porcelain=v1", "--untracked-files=all");
  if (!status) return;
  const entries = status.split(/\r?\n/);
  const preview = entries.slice(0, 12).map((entry) => `  ${entry}`).join("\n");
  const omitted = entries.length > 12 ? `\n  ... and ${entries.length - 12} more` : "";
  fail(
    "Refusing to generate provenance from a dirty Git worktree. " +
      "Commit or remove every tracked and non-ignored untracked change first.\n" +
      preview +
      omitted,
  );
}

function validateTimestamp(value) {
  if (!UTC_TIMESTAMP_PATTERN.test(value)) {
    fail(`SITE_BUILD_TIMESTAMP must be a second-precision UTC timestamp, received ${JSON.stringify(value)}`);
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.valueOf()) || parsed.toISOString().replace(".000Z", "Z") !== value) {
    fail(`SITE_BUILD_TIMESTAMP is not a valid calendar timestamp: ${value}`);
  }
}

function buildMetadata() {
  const sourceCommit = (process.env.SITE_SOURCE_COMMIT || git("rev-parse", "HEAD")).toLowerCase();
  let sourceBranch = process.env.SITE_SOURCE_BRANCH || git("rev-parse", "--abbrev-ref", "HEAD");
  if (sourceBranch === "HEAD") sourceBranch = "detached";
  const buildTimestamp = process.env.SITE_BUILD_TIMESTAMP || utcNowToSeconds();

  if (!SHA_PATTERN.test(sourceCommit)) {
    fail(`SITE_SOURCE_COMMIT must be a full lowercase Git SHA, received ${JSON.stringify(sourceCommit)}`);
  }
  if (!BRANCH_PATTERN.test(sourceBranch) || sourceBranch.includes("..") || sourceBranch.endsWith("/")) {
    fail(`SITE_SOURCE_BRANCH is not safe to publish: ${JSON.stringify(sourceBranch)}`);
  }
  validateTimestamp(buildTimestamp);

  return {
    sourceBranch,
    sourceCommit,
    buildTimestamp,
    generator: "mkdocs",
    repository: REPOSITORY,
  };
}

function assertContained(container, candidate, label) {
  const relative = path.relative(container, candidate);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
    fail(`${label} must remain below ${container}: ${candidate}`);
  }
}

function ensureSourceInsideRepository(source) {
  if (!fs.existsSync(source)) fail(`Required documentation source does not exist: ${source}`);
  const resolved = fs.realpathSync(source);
  const relative = path.relative(ROOT, resolved);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    fail(`Documentation source resolves outside the repository: ${source} -> ${resolved}`);
  }
}

function copyDereferenced(source, destination, ancestry = new Set()) {
  ensureSourceInsideRepository(source);
  assertContained(STAGING, destination, "Staging destination");

  const resolved = fs.realpathSync(source);
  const stat = fs.statSync(source);
  if (stat.isDirectory()) {
    if (ancestry.has(resolved)) fail(`Symlink cycle detected while staging ${source}`);
    const nextAncestry = new Set(ancestry);
    nextAncestry.add(resolved);
    fs.mkdirSync(destination, { recursive: true });
    const entries = fs.readdirSync(source).sort((left, right) => left.localeCompare(right, "en"));
    for (const entry of entries) {
      copyDereferenced(
        path.join(source, entry),
        path.join(destination, entry),
        nextAncestry,
      );
    }
    return;
  }
  if (!stat.isFile()) fail(`Unsupported documentation source type: ${source}`);
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.copyFileSync(source, destination);
}

function writeFile(destination, content) {
  assertContained(STAGING, destination, "Generated documentation destination");
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.writeFileSync(destination, content, "utf8");
}

function htmlEscape(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function prepare() {
  assertCleanWorktree();
  const metadata = buildMetadata();
  assertContained(PROJECT, STAGING, "Generated documentation directory");
  fs.rmSync(STAGING, { recursive: true, force: true });
  fs.mkdirSync(STAGING, { recursive: true });

  const directoryMappings = [
    ["appsec", "appsec"],
    ["cloud-security", "cloud-security"],
    ["devsecops", "devsecops"],
    ["docs", "docs"],
    ["labs", "labs"],
    ["threat-intel", "threat-intel"],
  ];
  for (const [source, destination] of directoryMappings) {
    copyDereferenced(path.join(ROOT, source), path.join(STAGING, destination));
  }

  copyDereferenced(path.join(ROOT, "README.md"), path.join(STAGING, "index.md"));
  copyDereferenced(
    path.join(PROJECT, "docs", "css"),
    path.join(STAGING, "css"),
  );
  copyDereferenced(
    path.join(PROJECT, "docs", "CNAME"),
    path.join(STAGING, "CNAME"),
  );

  writeFile(
    path.join(STAGING, "site-meta.json"),
    `${JSON.stringify(metadata, null, 2)}\n`,
  );

  const commitUrl = `${REPOSITORY_URL}/commit/${metadata.sourceCommit}`;
  const about = [
    "<!-- Generated by scripts/prepare-mkdocs.js. Do not edit this staged file. -->",
    "",
    "# Build provenance",
    "",
    "This page identifies the exact source revision used to generate this site.",
    "The repository remains the authoritative source; `gh-pages` contains generated output only.",
    "",
    "| Item | Value |",
    "|---|---|",
    `| Source branch | \`${metadata.sourceBranch}\` |`,
    `| Source commit | [\`${metadata.sourceCommit}\`](${commitUrl}) |`,
    `| Build timestamp | \`${metadata.buildTimestamp}\` |`,
    `| Generator | \`${metadata.generator}\` |`,
    `| Repository | [\`${metadata.repository}\`](${REPOSITORY_URL}) |`,
    "",
    "The machine-readable form is available as [`site-meta.json`](../site-meta.json).",
    "",
    "A successful build proves that repository validation and static-site generation completed for",
    "this revision. It is not evidence that every conceptual example was deployed to a cloud",
    "environment; individual articles state their own implementation and validation status.",
    "",
  ].join("\n");
  writeFile(path.join(STAGING, "about", "site-provenance.md"), about);

  const escapedCommit = htmlEscape(metadata.sourceCommit);
  const escapedTimestamp = htmlEscape(metadata.buildTimestamp);
  const escapedRepository = htmlEscape(metadata.repository);
  const escapedRepositoryUrl = htmlEscape(REPOSITORY_URL);
  const escapedCommitUrl = htmlEscape(commitUrl);
  const footer = [
    "<div class=\"md-copyright__highlight site-provenance\"",
    `     data-source-commit="${escapedCommit}"`,
    `     data-build-timestamp="${escapedTimestamp}">`,
    "  Source",
    `  <a href="${escapedCommitUrl}"><code>${escapedCommit}</code></a>`,
    "  &middot; Built",
    `  <a href="{{ 'about/site-provenance/' | url }}"><time datetime="${escapedTimestamp}">${escapedTimestamp}</time></a>`,
    "  &middot;",
    `  <a href="${escapedRepositoryUrl}">${escapedRepository}</a>`,
    "  &middot;",
    "  <a href=\"{{ 'site-meta.json' | url }}\">site-meta.json</a>",
    "</div>",
    "",
  ].join("\n");
  fs.mkdirSync(path.dirname(GENERATED_FOOTER), { recursive: true });
  fs.writeFileSync(GENERATED_FOOTER, footer, "utf8");

  console.log(
    `Prepared cross-platform MkDocs staging for ${metadata.sourceBranch}@${metadata.sourceCommit} (${metadata.buildTimestamp}).`,
  );
}

try {
  prepare();
} catch (error) {
  console.error(`MkDocs staging failed: ${error.message}`);
  process.exit(1);
}
