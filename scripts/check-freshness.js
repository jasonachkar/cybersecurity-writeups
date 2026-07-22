"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { ROOT, isIndexed, markdownFiles, parseDocument, relative } = require("./content-lib");
const registry = JSON.parse(fs.readFileSync(path.join(ROOT, "docs", "content-metadata.json"), "utf8"));
const today = new Date();
const stale = [];
let checked = 0;

for (const file of markdownFiles()) {
  const document = parseDocument(file);
  if (!isIndexed(file, document)) continue;
  checked += 1;
  const rel = relative(file);
  const metadata = { ...(registry[rel] || {}), ...(document.metadata || {}) };
  if (!metadata.lastReviewed || !Number.isInteger(metadata.reviewIntervalDays)) continue;
  const reviewed = new Date(`${metadata.lastReviewed}T00:00:00Z`);
  const ageDays = Math.floor((today - reviewed) / 86_400_000);
  if (ageDays > metadata.reviewIntervalDays) stale.push(`${rel} (${ageDays} days; interval ${metadata.reviewIntervalDays})`);
}
if (stale.length) {
  console.warn(`Freshness warning: ${stale.length} article(s) exceeded their review interval:`);
  for (const item of stale) console.warn(`- ${item}`);
} else {
  console.log(`Freshness check passed for ${checked} indexed article(s).`);
}
