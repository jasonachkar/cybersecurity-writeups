"use strict";

const { isIndexed, markdownFiles, parseDocument, relative } = require("./content-lib");

const FLAGSHIPS = new Set([
  "docs/tutorials/azure-landing-zone/README.md",
  "devsecops/secure-cicd-pipeline-design.md",
  "devsecops/supply-chain-sbom-signing.md",
  "appsec/saas-multitenancy-isolation.md",
]);
const FLAGSHIP_CONCEPTS = [
  ["scope", /^##+\s+.*scope/im],
  ["threat model", /^##+\s+.*threat/im],
  ["decision record", /^##+\s+.*(?:decision|adr)/im],
  ["failure modes", /^##+\s+.*failure/im],
  ["validation", /^##+\s+.*validation/im],
  ["operations", /^##+\s+.*(?:operations|observability)/im],
  ["limitations", /^##+\s+.*limitations/im],
  ["references", /^##+\s+references/im],
];
const errors = [];
const warnings = [];
let checked = 0;

for (const file of markdownFiles()) {
  const document = parseDocument(file);
  if (!isIndexed(file, document)) continue;
  checked += 1;
  const rel = relative(file);
  const verified = ["verified", "partially-verified"].includes(document.metadata.reviewStatus);
  if (!/^##+\s+References/im.test(document.body)) {
    const message = `${rel}: no References section`;
    if (verified) errors.push(message);
    else warnings.push(message);
  }
  if (verified && !/https:\/\//i.test(document.body)) errors.push(`${rel}: verified article has no HTTPS source link`);
  if (document.metadata.implementationStatus === "tested" && !/(?:labs?|tests?)[\\/]/i.test(document.body)) {
    errors.push(`${rel}: tested implementation does not link a lab or test path`);
  }
  if (FLAGSHIPS.has(rel)) {
    for (const [name, pattern] of FLAGSHIP_CONCEPTS) {
      if (!pattern.test(document.body)) errors.push(`${rel}: flagship missing ${name} section`);
    }
  }
}

if (warnings.length) {
  console.warn(`Research-structure warnings (${warnings.length}) for legacy review-required content:`);
  for (const item of warnings) console.warn(`- ${item}`);
}
if (errors.length) {
  console.error(`Research-structure validation failed with ${errors.length} error(s):`);
  for (const item of errors) console.error(`- ${item}`);
  process.exit(1);
}
console.log(`Research-structure validation passed for ${checked} indexed article(s).`);
