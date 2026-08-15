"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { ROOT, isIndexed, markdownFiles, parseDocument, relative } = require("./content-lib");

const REQUIRED = ["title", "type", "tags", "date", "lastReviewed", "reviewStatus", "validatedAgainst", "sourceQuality", "implementationStatus", "reviewIntervalDays"];
const PRIMARY_RESEARCH = /^(appsec|cloud-security|devsecops|threat-intel)\/[^/]+\.md$/;
const TYPES = new Set(["cloud-security", "appsec", "devsecops", "threat-intel", "tutorial", "research", "certification-notes"]);
const REVIEW = new Set(["verified", "partially-verified", "requires-review", "historical"]);
const QUALITY = new Set(["primary-sources-reviewed", "mixed-sources", "requires-review"]);
const IMPLEMENTATION = new Set(["tested", "partially-tested", "illustrative", "pseudocode"]);
const DATE_PATTERN = /^\d{4}-\d{2}-\d{2}$/;
const LEGACY_DATE_PATTERN = /^\d{4}-\d{2}$/;
const today = new Date().toISOString().slice(0, 10);
const registryPath = path.join(ROOT, "docs", "content-metadata.json");
const registry = JSON.parse(fs.readFileSync(registryPath, "utf8"));
const errors = [];
const titles = new Map();
const seenRegistry = new Set();
let checked = 0;

function error(file, message) { errors.push(`${relative(file)}: ${message}`); }

for (const file of markdownFiles()) {
  const document = parseDocument(file);
  if (document.parseError) error(file, `invalid YAML front matter: ${document.parseError.message}`);
  if (!isIndexed(file, document)) continue;
  checked += 1;
  const rel = relative(file);
  const registryMetadata = registry[rel] || {};
  if (registry[rel]) seenRegistry.add(rel);
  const metadata = { ...registryMetadata, ...(document.metadata || {}) };
  const primaryResearch = PRIMARY_RESEARCH.test(rel) && !rel.endsWith("/index.md");
  for (const field of REQUIRED) {
    if (metadata[field] === undefined || metadata[field] === null || metadata[field] === "") error(file, `missing required field ${field}`);
  }
  for (const field of primaryResearch ? ["id", "navTitle", "order"] : ["readingTime"]) {
    if (metadata[field] === undefined || metadata[field] === null || metadata[field] === "") error(file, `missing required field ${field}`);
  }
  if (registry[rel] && registryMetadata.reviewStatus !== "requires-review") error(file, "legacy registry entries may not claim verification; move reviewed metadata into page front matter");
  if (!TYPES.has(metadata.type)) error(file, `unsupported type ${JSON.stringify(metadata.type)}`);
  if (!REVIEW.has(metadata.reviewStatus)) error(file, `unsupported reviewStatus ${JSON.stringify(metadata.reviewStatus)}`);
  if (!QUALITY.has(metadata.sourceQuality)) error(file, `unsupported sourceQuality ${JSON.stringify(metadata.sourceQuality)}`);
  if (!IMPLEMENTATION.has(metadata.implementationStatus)) error(file, `unsupported implementationStatus ${JSON.stringify(metadata.implementationStatus)}`);
  if (!Array.isArray(metadata.tags) || metadata.tags.length === 0) error(file, "tags must be a nonempty list");
  if (!Array.isArray(metadata.validatedAgainst)) error(file, "validatedAgainst must be a list");
  if (["verified", "partially-verified"].includes(metadata.reviewStatus) && (!metadata.validatedAgainst || metadata.validatedAgainst.length === 0)) error(file, `${metadata.reviewStatus} content must list validation evidence`);
  if (metadata.reviewStatus === "verified" && metadata.sourceQuality !== "primary-sources-reviewed") error(file, "verified content must use sourceQuality primary-sources-reviewed");
  if (!DATE_PATTERN.test(String(metadata.lastReviewed || ""))) error(file, "lastReviewed must use YYYY-MM-DD");
  const publicationDate = String(metadata.date || "");
  if (!DATE_PATTERN.test(publicationDate) && !(registry[rel] && LEGACY_DATE_PATTERN.test(publicationDate))) error(file, "date must use YYYY-MM-DD (legacy registry pages may preserve YYYY-MM)");
  if (metadata.lastReviewed > today) error(file, `lastReviewed ${metadata.lastReviewed} is in the future`);
  if (metadata.readingTime !== undefined && (!Number.isInteger(metadata.readingTime) || metadata.readingTime < 1)) error(file, "readingTime must be a positive integer when supplied");
  if (primaryResearch && (!Number.isInteger(metadata.order) || metadata.order < 1)) error(file, "order must be a positive integer");
  if (!Number.isInteger(metadata.reviewIntervalDays) || metadata.reviewIntervalDays < 1) error(file, "reviewIntervalDays must be a positive integer");
  const normalizedTitle = String(metadata.title || "").trim().toLowerCase();
  if (titles.has(normalizedTitle)) error(file, `duplicate title also used by ${titles.get(normalizedTitle)}`);
  else titles.set(normalizedTitle, rel);
}
for (const rel of Object.keys(registry)) if (!seenRegistry.has(rel)) errors.push(`docs/content-metadata.json: stale or non-indexed entry ${rel}`);
if (errors.length) {
  console.error(`Metadata validation failed with ${errors.length} error(s):`);
  for (const item of errors) console.error(`- ${item}`);
  process.exit(1);
}
console.log(`Metadata validation passed for ${checked} indexed article(s); ${seenRegistry.size} legacy page(s) remain explicitly requires-review.`);
