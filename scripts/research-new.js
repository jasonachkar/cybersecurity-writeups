#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const YAML = require("yaml");
const { ROOT, parseDocument } = require("./content-lib");

const DOMAINS = new Set(["appsec", "cloud-security", "devsecops", "threat-intel"]);
const SLUG = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

function parseArguments(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const key = argv[index];
    if (!key.startsWith("--") || !argv[index + 1]) throw new Error(`expected a value after ${key}`);
    options[key.slice(2)] = argv[index + 1];
    index += 1;
  }
  for (const field of ["domain", "slug", "title"]) {
    if (!options[field]) throw new Error(`missing required --${field}`);
  }
  if (!DOMAINS.has(options.domain)) throw new Error(`unsupported domain ${JSON.stringify(options.domain)}`);
  if (!SLUG.test(options.slug)) throw new Error("slug must use lowercase kebab-case");
  if (!options.title.trim() || /[\r\n]/.test(options.title)) throw new Error("title must be a nonempty single line");
  return options;
}

function nextOrder(root, domain) {
  const orders = fs.readdirSync(path.join(root, domain))
    .filter(name => name.endsWith(".md") && name !== "index.md")
    .map(name => parseDocument(path.join(root, domain, name)).metadata?.order)
    .filter(Number.isInteger);
  return (orders.length ? Math.max(...orders) : 0) + 10;
}

function article({domain, slug, title}, root = ROOT, date = new Date().toISOString().slice(0, 10)) {
  const target = path.join(root, domain, `${slug}.md`);
  if (fs.existsSync(target)) throw new Error(`article already exists: ${path.relative(root, target)}`);
  const metadata = {
    title: title.trim(), id: slug, navTitle: title.trim(), order: nextOrder(root, domain),
    type: domain, tags: [slug], date, lastReviewed: date,
    reviewStatus: "requires-review", validatedAgainst: [], sourceQuality: "requires-review",
    implementationStatus: "illustrative", reviewIntervalDays: 180,
  };
  const frontmatter = YAML.stringify(metadata, {lineWidth: 0}).trimEnd();
  const body = `---\n${frontmatter}\n---\n\n# ${metadata.title}\n\nState the security decision, its scope, and the evidence needed to review it.\n\n## Decision and context\n\nDescribe the trust boundaries, assumptions, and non-goals.\n\n## Threats and controls\n\nMap concrete abuse cases to controls and record residual risk.\n\n## Validation and limitations\n\nLabel examples and document what was tested, what failed safely, and what remains illustrative.\n\n## References\n\n- Add primary sources reviewed for consequential claims.\n`;
  return {target, relative: path.relative(root, target).replace(/\\/g, "/"), body, metadata};
}

function createResearch(argv, root = ROOT, date) {
  const result = article(parseArguments(argv), root, date);
  fs.writeFileSync(result.target, result.body, {encoding: "utf8", flag: "wx"});
  return result;
}

if (require.main === module) {
  try {
    const result = createResearch(process.argv.slice(2));
    console.log(`Created ${result.relative}`);
    console.log("Preview: npm run docs:serve");
    console.log("Validate: npm run verify:docs");
  } catch (error) {
    console.error(`research:new: ${error.message}`);
    process.exit(1);
  }
}

module.exports = { article, createResearch, nextOrder, parseArguments };
