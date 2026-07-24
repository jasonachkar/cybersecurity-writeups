"use strict";

const fs = require("node:fs");
const path = require("node:path");
const YAML = require("yaml");

const ROOT = path.resolve(__dirname, "..");
const CONTENT_ROOTS = ["appsec", "cloud-security", "devsecops", "threat-intel", "docs"];
const EXCLUDED_DIRECTORIES = new Set([
  ".git",
  ".idea",
  ".terraform",
  ".tools",
  ".venv",
  "__pycache__",
  "generated-docs",
  "node_modules",
  "site",
]);

function walk(directory, predicate = () => true) {
  if (!fs.existsSync(directory)) return [];
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && EXCLUDED_DIRECTORIES.has(entry.name)) continue;
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...walk(absolute, predicate));
    else if (predicate(absolute)) files.push(absolute);
  }
  return files;
}

function markdownFiles() {
  return CONTENT_ROOTS.flatMap((directory) =>
    walk(path.join(ROOT, directory), (file) => file.endsWith(".md")),
  ).sort();
}

function allRepositoryFiles(predicate = () => true) {
  return walk(ROOT, predicate).sort();
}

function relative(file) {
  return path.relative(ROOT, file).replace(/\\/g, "/");
}

function parseDocument(file) {
  const raw = fs.readFileSync(file, "utf8");
  const match = raw.match(/^---\s*\r?\n([\s\S]*?)\r?\n---\s*\r?\n/);
  let metadata = null;
  let body = raw;
  let parseError = null;
  if (match) {
    try {
      metadata = YAML.parse(match[1]);
    } catch (error) {
      parseError = error;
    }
    body = raw.slice(match[0].length);
  }
  return { raw, body, metadata, parseError };
}

function isIndexed(file, document) {
  const rel = relative(file);
  if (!document.metadata) return false;
  if (/^(appsec|cloud-security|devsecops|threat-intel)\/[^/]+\.md$/.test(rel)) return true;
  return /^docs\/.+\/README\.md$/.test(rel);
}

module.exports = {
  ROOT,
  allRepositoryFiles,
  isIndexed,
  markdownFiles,
  parseDocument,
  relative,
  walk,
};
