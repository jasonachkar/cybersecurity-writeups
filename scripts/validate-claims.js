#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { ROOT, markdownFiles, relative } = require("./content-lib");

const REPORT_PATH = path.join(ROOT, "docs", "research-audit", "strong-claim-review.md");
const DECISIONS_PATH = path.join(
  ROOT,
  "docs",
  "research-audit",
  "claim-review-decisions.json",
);
const EXCLUDED = new Set([
  "docs/CONTRIBUTING_SECURITY_CONTENT.md",
  "docs/research-audit/content-inventory.md",
  "docs/research-audit/modernization-completion-report.md",
  "docs/research-audit/strong-claim-review.md",
]);
const TERMS = [
  ["production-ready", /\bproduction[- ]ready\b/gi],
  ["enterprise-ready", /\benterprise[- ]ready\b/gi],
  ["guarantee", /\bguarantee(?:d|s)?\b/gi],
  ["fully prevents", /\bfully\s+prevents?\b/gi],
  ["prevents", /\bprevents?\b/gi],
  ["always", /\balways\b/gi],
  ["never", /\bnever\b/gi],
  ["automatically", /\bautomatically\b/gi],
  ["impossible", /\bimpossible\b/gi],
  ["cannot", /\bcannot\b/gi],
  ["must", /\bmust\b/gi],
  ["deploy this", /\bdeploy\s+this\b/gi],
  ["correct way", /\bcorrect\s+way\b/gi],
  ["absolute isolation", /\babsolute\s+isolation\b/gi],
  ["complete protection", /\bcomplete\s+protection\b/gi],
  ["secure", /\bsecure\b/gi],
];

function loadFileReviews() {
  const document = JSON.parse(fs.readFileSync(DECISIONS_PATH, "utf8"));
  if (!document || typeof document !== "object" || Array.isArray(document)) {
    throw new Error("claim-review-decisions.json must contain one object");
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(document.reviewedThrough || "")) {
    throw new Error("claim-review-decisions.json reviewedThrough must be YYYY-MM-DD");
  }
  if (!document.files || typeof document.files !== "object" || Array.isArray(document.files)) {
    throw new Error("claim-review-decisions.json files must be an object");
  }
  const reviews = new Map();
  for (const [filePath, justification] of Object.entries(document.files)) {
    if (path.isAbsolute(filePath) || filePath.includes("\\") || filePath.includes("..")) {
      throw new Error(`Unsafe claim-review path: ${filePath}`);
    }
    const absolute = path.join(ROOT, ...filePath.split("/"));
    if (!fs.existsSync(absolute)) {
      throw new Error(`Claim-review decision targets a missing file: ${filePath}`);
    }
    if (typeof justification !== "string" || justification.trim().length < 24) {
      throw new Error(`Claim-review justification is too short for ${filePath}`);
    }
    reviews.set(filePath, justification.trim());
  }
  return reviews;
}

function stripNonProse(lines) {
  let fence = false;
  return lines.map((line) => {
    if (/^\s*(```|~~~)/.test(line)) {
      fence = !fence;
      return "";
    }
    if (fence) return "";
    return line
      .replace(/`[^`]*`/g, "")
      .replace(/https?:\/\/\S+/g, "")
      .replace(/<!--\s*claim-reviewed:[\s\S]*?-->/gi, "");
  });
}

function inlineSuppression(lines, index) {
  for (const candidate of [lines[index], lines[index - 1] || ""]) {
    const match = candidate.match(/<!--\s*claim-reviewed:\s*([^>]+?)\s*-->/i);
    if (match && match[1].trim().length >= 12) return match[1].trim();
  }
  return null;
}

function tableText(value) {
  return value
    .replace(/!?\[([^\]]*)\]\([^)]+\)/g, "$1")
    .replace(/&/g, "&amp;")
    .replace(/\|/g, "\\|")
    .replace(/\[/g, "\\[")
    .replace(/\]/g, "\\]")
    .replace(/\(/g, "&#40;")
    .replace(/\)/g, "&#41;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function scan(fileReviews) {
  const findings = [];
  for (const file of markdownFiles()) {
    const filePath = relative(file);
    if (EXCLUDED.has(filePath)) continue;
    const rawLines = fs.readFileSync(file, "utf8").split(/\r?\n/);
    const proseLines = stripNonProse(rawLines);
    proseLines.forEach((line, index) => {
      for (const [term, pattern] of TERMS) {
        pattern.lastIndex = 0;
        if (!pattern.test(line)) continue;
        const reason =
          inlineSuppression(rawLines, index) ||
          fileReviews.get(filePath) ||
          null;
        findings.push({
          path: filePath,
          line: index + 1,
          term,
          status: reason ? "reviewed" : "review-required",
          justification: reason || "",
          context: line.trim().slice(0, 180),
        });
      }
    });
  }
  return findings.sort((left, right) =>
    left.path.localeCompare(right.path) ||
    left.line - right.line ||
    left.term.localeCompare(right.term),
  );
}

function report(findings, fileReviewCount) {
  const counts = new Map();
  for (const finding of findings) {
    const current = counts.get(finding.term) || { total: 0, reviewed: 0 };
    current.total += 1;
    if (finding.status === "reviewed") current.reviewed += 1;
    counts.set(finding.term, current);
  }
  const digest = crypto
    .createHash("sha256")
    .update(JSON.stringify(findings))
    .digest("hex");
  const lines = [
    "# Strong security claim review queue",
    "",
    "Generated by `node scripts/validate-claims.js --write`.",
    "",
    "> A match is a review signal, not proof that a sentence is wrong. Fenced code,",
    "> inline code, URLs, and this generated report are excluded. A finding is marked",
    "> reviewed by an adjacent `claim-reviewed` comment or an explicit file-level",
    "> rationale in `claim-review-decisions.json`. File-level review records bounded",
    "> technical review; it does not claim production deployment.",
    "",
    `File-level review decisions: ${fileReviewCount}`,
    "",
    `Scan digest: \`${digest}\``,
    "",
    "## Summary",
    "",
    "| Term | Matches | Reviewed | Review required |",
    "| --- | ---: | ---: | ---: |",
  ];
  for (const [term, count] of [...counts.entries()].sort()) {
    lines.push(
      `| ${term} | ${count.total} | ${count.reviewed} | ${count.total - count.reviewed} |`,
    );
  }
  lines.push(
    "",
    "## Findings",
    "",
    "| Location | Term | Status | Context / justification |",
    "| --- | --- | --- | --- |",
  );
  for (const finding of findings) {
    const detail = tableText(
      finding.justification || finding.context || "(empty line)",
    );
    lines.push(
      `| \`${finding.path}:${finding.line}\` | ${finding.term} | ` +
      `${finding.status} | ${detail} |`,
    );
  }
  lines.push("");
  return lines.join("\n");
}

let fileReviews;
try {
  fileReviews = loadFileReviews();
} catch (error) {
  console.error(`Strong-claim decision validation failed: ${error.message}`);
  process.exit(1);
}
const findings = scan(fileReviews);
const output = report(findings, fileReviews.size);
const write = process.argv.includes("--write");
const check = process.argv.includes("--check");
const strict = process.argv.includes("--strict");

if (write) {
  fs.writeFileSync(REPORT_PATH, output, "utf8");
  console.log(`Wrote ${relative(REPORT_PATH)} with ${findings.length} claim signal(s).`);
}

if (check) {
  const current = fs.existsSync(REPORT_PATH)
    ? fs.readFileSync(REPORT_PATH, "utf8")
    : null;
  if (current !== output) {
    console.error(
      "Strong-claim report is stale. Run node scripts/validate-claims.js --write.",
    );
    process.exit(1);
  }
}

const unresolved = findings.filter((finding) => finding.status === "review-required");
console.log(
  `Strong-claim scan: ${findings.length} signal(s), ` +
  `${findings.length - unresolved.length} reviewed, ${unresolved.length} queued.`,
);
for (const finding of unresolved.slice(0, 20)) {
  console.warn(`Claim review: ${finding.path}:${finding.line} [${finding.term}]`);
}
if (unresolved.length > 20) {
  console.warn(`Claim review: ${unresolved.length - 20} additional signal(s) are in the report.`);
}
if (strict && unresolved.length) process.exit(2);
