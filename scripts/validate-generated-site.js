"use strict";

const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");
const SITE_DIRECTORY = path.resolve(
  process.argv[2] || path.join(ROOT, "mkdocs-project", "site"),
);
const SITE_URL = (process.env.SITE_URL || "https://docs.jasonachkardiab.com").replace(/\/+$/, "");
const EXPECTED_CNAME = new URL(SITE_URL).hostname;
const EXPECTED_REPOSITORY = "jasonachkar/cybersecurity-writeups";
const EXPECTED_REPOSITORY_URL = `https://github.com/${EXPECTED_REPOSITORY}`;
const EXPECTED_KEYS = [
  "buildTimestamp",
  "generator",
  "repository",
  "sourceBranch",
  "sourceCommit",
];
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const UTC_TIMESTAMP_PATTERN =
  /^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\dZ$/;
const errors = [];

function error(message) {
  errors.push(message);
}

function readRequired(relativePath) {
  const absolute = path.join(SITE_DIRECTORY, ...relativePath.split("/"));
  if (!fs.existsSync(absolute)) {
    error(`missing required generated file ${relativePath}`);
    return "";
  }
  return fs.readFileSync(absolute, "utf8");
}

function validateTimestamp(value) {
  if (typeof value !== "string" || !UTC_TIMESTAMP_PATTERN.test(value)) return false;
  const parsed = new Date(value);
  return (
    !Number.isNaN(parsed.valueOf()) &&
    parsed.toISOString().replace(".000Z", "Z") === value &&
    parsed.valueOf() <= Date.now() + 5 * 60 * 1000
  );
}

function collectFiles(directory, prefix = "") {
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true }).sort((a, b) =>
    a.name.localeCompare(b.name, "en"),
  )) {
    if (entry.name === ".git") continue;
    const absolute = path.join(directory, entry.name);
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
    const stat = fs.lstatSync(absolute);
    if (stat.isSymbolicLink()) {
      error(`generated output must not contain symlinks: ${relative}`);
      continue;
    }
    if (stat.isDirectory()) files.push(...collectFiles(absolute, relative));
    else if (stat.isFile()) files.push(relative);
    else error(`generated output contains unsupported file type: ${relative}`);
  }
  return files;
}

function attributes(tag) {
  const values = new Map();
  const pattern = /([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
  let match;
  while ((match = pattern.exec(tag))) values.set(match[1].toLowerCase(), match[2] ?? match[3]);
  return values;
}

function canonicalLinks(html) {
  const canonicals = [];
  for (const match of html.matchAll(/<link\b[^>]*>/gi)) {
    const values = attributes(match[0]);
    const rel = (values.get("rel") || "").toLowerCase().split(/\s+/);
    if (rel.includes("canonical")) canonicals.push(values.get("href") || "");
  }
  return canonicals;
}

function expectedCanonical(relativePath) {
  if (relativePath === "index.html") return `${SITE_URL}/`;
  if (relativePath.endsWith("/index.html")) {
    return `${SITE_URL}/${relativePath.slice(0, -"index.html".length)}`;
  }
  return `${SITE_URL}/${relativePath}`;
}

function parseSitemapLocations(xml) {
  return [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) =>
    match[1].replaceAll("&amp;", "&"),
  );
}

function validate() {
  if (!fs.existsSync(SITE_DIRECTORY) || !fs.statSync(SITE_DIRECTORY).isDirectory()) {
    throw new Error(`Generated site directory does not exist: ${SITE_DIRECTORY}`);
  }

  const files = collectFiles(SITE_DIRECTORY);
  if (files.includes("stale-output-sentinel.html")) {
    error("strict clean build retained stale-output-sentinel.html");
  }
  if (!files.includes(".nojekyll")) error("missing .nojekyll");

  const cname = readRequired("CNAME").trim();
  if (cname !== EXPECTED_CNAME) {
    error(`CNAME must be ${EXPECTED_CNAME}, received ${JSON.stringify(cname)}`);
  }

  let metadata = {};
  const metadataSource = readRequired("site-meta.json");
  if (metadataSource) {
    try {
      metadata = JSON.parse(metadataSource);
    } catch (parseError) {
      error(`site-meta.json is invalid JSON: ${parseError.message}`);
    }
  }
  if (!metadata || Array.isArray(metadata) || typeof metadata !== "object") {
    error("site-meta.json must contain one JSON object");
    metadata = {};
  }
  const actualKeys = Object.keys(metadata).sort();
  if (JSON.stringify(actualKeys) !== JSON.stringify(EXPECTED_KEYS)) {
    error(`site-meta.json keys must be exactly ${EXPECTED_KEYS.join(", ")}`);
  }
  if (!SHA_PATTERN.test(metadata.sourceCommit || "")) {
    error("site-meta.json sourceCommit must be a full lowercase Git SHA");
  }
  if (process.env.SITE_SOURCE_COMMIT &&
      metadata.sourceCommit !== process.env.SITE_SOURCE_COMMIT.toLowerCase()) {
    error(`site-meta.json sourceCommit does not match SITE_SOURCE_COMMIT ${process.env.SITE_SOURCE_COMMIT}`);
  }
  if (!metadata.sourceBranch || typeof metadata.sourceBranch !== "string") {
    error("site-meta.json sourceBranch must be a nonempty string");
  }
  if (process.env.SITE_SOURCE_BRANCH &&
      metadata.sourceBranch !== process.env.SITE_SOURCE_BRANCH) {
    error(`site-meta.json sourceBranch does not match SITE_SOURCE_BRANCH ${process.env.SITE_SOURCE_BRANCH}`);
  }
  if (!validateTimestamp(metadata.buildTimestamp)) {
    error("site-meta.json buildTimestamp must be a valid, non-future, second-precision UTC timestamp");
  }
  if (process.env.SITE_BUILD_TIMESTAMP &&
      metadata.buildTimestamp !== process.env.SITE_BUILD_TIMESTAMP) {
    error(`site-meta.json buildTimestamp does not match SITE_BUILD_TIMESTAMP ${process.env.SITE_BUILD_TIMESTAMP}`);
  }
  if (metadata.generator !== "mkdocs") error('site-meta.json generator must be "mkdocs"');
  if (metadata.repository !== EXPECTED_REPOSITORY) {
    error(`site-meta.json repository must be ${EXPECTED_REPOSITORY}`);
  }

  const htmlFiles = files.filter((file) => file.endsWith(".html"));
  if (htmlFiles.length === 0) error("generated site contains no HTML pages");
  const canonicalSet = new Set();
  for (const htmlFile of htmlFiles) {
    const html = readRequired(htmlFile);
    const canonicals = canonicalLinks(html);
    if (htmlFile === "404.html") {
      if (canonicals.some((canonical) => !canonical.startsWith(`${SITE_URL}/`))) {
        error("404.html contains a canonical URL outside the production site");
      }
      continue;
    }
    if (canonicals.length !== 1) {
      error(`${htmlFile} must contain exactly one canonical link; found ${canonicals.length}`);
    } else {
      const expected = expectedCanonical(htmlFile);
      if (canonicals[0] !== expected) {
        error(`${htmlFile} canonical must be ${expected}, received ${canonicals[0]}`);
      }
      if (canonicalSet.has(canonicals[0])) error(`duplicate canonical URL ${canonicals[0]}`);
      canonicalSet.add(canonicals[0]);
    }
    if (!html.includes(EXPECTED_REPOSITORY_URL)) {
      error(`${htmlFile} does not link to the source repository`);
    }
    if (metadata.sourceCommit && !html.includes(metadata.sourceCommit)) {
      error(`${htmlFile} does not expose the full source commit in its footer`);
    }
    if (metadata.buildTimestamp && !html.includes(metadata.buildTimestamp)) {
      error(`${htmlFile} does not expose the UTC build timestamp in its footer`);
    }
    if (!html.includes("site-meta.json")) {
      error(`${htmlFile} does not link to site-meta.json`);
    }
  }

  const aboutPath = "about/site-provenance/index.html";
  if (!files.includes(aboutPath)) error(`missing public provenance page ${aboutPath}`);

  const sitemap = readRequired("sitemap.xml");
  const sitemapLocations = parseSitemapLocations(sitemap);
  if (sitemapLocations.length === 0) error("sitemap.xml contains no locations");
  const sitemapSet = new Set();
  for (const location of sitemapLocations) {
    if (!location.startsWith(`${SITE_URL}/`)) {
      error(`sitemap.xml contains a non-production URL: ${location}`);
    }
    if (sitemapSet.has(location)) error(`sitemap.xml contains duplicate location ${location}`);
    sitemapSet.add(location);
  }
  for (const canonical of canonicalSet) {
    if (!sitemapSet.has(canonical)) error(`sitemap.xml omits canonical page ${canonical}`);
  }
  for (const location of sitemapSet) {
    if (!canonicalSet.has(location)) error(`sitemap.xml contains a URL without a generated canonical page: ${location}`);
  }

  if (errors.length) {
    console.error(`Generated-site validation failed with ${errors.length} error(s):`);
    for (const item of errors) console.error(`- ${item}`);
    process.exit(1);
  }
  console.log(
    `Generated-site validation passed for ${htmlFiles.length} HTML page(s) at ${metadata.sourceCommit}.`,
  );
}

try {
  validate();
} catch (caught) {
  console.error(`Generated-site validation failed: ${caught.message}`);
  process.exit(1);
}
