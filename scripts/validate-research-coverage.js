"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const {buildCatalog} = require("./docs-catalog-lib");
const {ROOT, parseDocument} = require("./content-lib");
const rows = JSON.parse(fs.readFileSync(path.join(ROOT, "research-methodology/research-coverage.json"), "utf8"));
const existing = buildCatalog().research.filter(item => item.domain !== "vulnerability-research");
assert.equal(new Set(rows.map(row => row.article)).size, rows.length, "duplicate coverage entry");
assert.deepEqual(rows.map(row => row.article).sort(), existing.map(item => item.sourcePath).sort(), "every maintained article requires a protocol mapping");
for (const row of rows) {
  const article = parseDocument(path.join(ROOT, row.article));
  const body = article.body;
  for (const section of ["Research question and hypothesis", "Research threat model", "Method and evidence requirements", "Findings and interpretation", "Practical guidance and failure containment", "Limitations and what was not tested", "Open questions"]) {
    assert.ok(body.includes(`## ${section}`), `${row.article}: missing ${section}`);
  }
  assert.ok(body.includes(row.question) && body.includes(row.command), `${row.article}: protocol diverged from mapping`);
  assert.ok(fs.existsSync(path.join(ROOT, row.lab)), `${row.article}: missing related lab`);
  const lab = fs.readFileSync(path.join(ROOT, row.lab), "utf8");
  assert.ok(lab.includes(row.article) || lab.includes(article.metadata.id), `${row.lab}: missing research backlink`);
  assert.match(body, /T0.*|T1.*/);
}
for (const item of buildCatalog().research.filter(candidate => candidate.domain === "vulnerability-research")) {
  const body = parseDocument(path.join(ROOT, item.sourcePath)).body;
  for (const concept of [/## Executive summary/, /## Research question and hypothesis/, /## Threat model/, /##.*[Rr]oot.cause/, /##.*[Ll]imitations/, /## Open questions/, /## References/]) assert.match(body, concept, item.sourcePath);
  assert.ok(item.related.labs.length > 0, `${item.sourcePath}: no catalog lab relation`);
}
console.log(`Research coverage passed: ${rows.length} maintained protocols and 3 vulnerability studies; headings are not factual verification.`);
