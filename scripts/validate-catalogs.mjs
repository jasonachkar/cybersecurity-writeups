// Validates the Scripts and Labs catalogues (scripts/catalog.mjs, labs/catalog.mjs)
// and the pages generated from them: every source path is real, slugs/pages are
// unique, every maintained lab is catalogued, the source viewer renders before
// its page's explanatory sections, and the search index never picked up a
// full source-code body.
import fs from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {SCRIPTS, SCRIPT_CATEGORIES} from "./catalog.mjs";
import {LABS} from "../labs/catalog.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const errors = [];
const fail = message => errors.push(message);

// --- Scripts catalogue -------------------------------------------------
const scriptSlugs = new Set();
for (const script of SCRIPTS) {
  if (!SCRIPT_CATEGORIES.some(category => category.slug === script.category)) {
    fail(`scripts/catalog.mjs: "${script.slug}" references unknown category "${script.category}"`);
  }
  const dupeKey = `${script.category}/${script.slug}`;
  if (scriptSlugs.has(dupeKey)) fail(`scripts/catalog.mjs: duplicate script slug "${dupeKey}"`);
  scriptSlugs.add(dupeKey);
  if (!script.sourceFiles || !script.sourceFiles.length) fail(`scripts/catalog.mjs: "${script.slug}" has no sourceFiles`);
  if (!script.sourceFiles.some(file => file.primary)) fail(`scripts/catalog.mjs: "${script.slug}" has no primary source file`);
  for (const file of script.sourceFiles || []) {
    const resolved = path.resolve(root, file.path);
    if (!resolved.startsWith(root)) fail(`scripts/catalog.mjs: "${script.slug}" source path escapes repository root: ${file.path}`);
    if (!fs.existsSync(path.join(root, file.path))) fail(`scripts/catalog.mjs: "${script.slug}" source file does not exist: ${file.path}`);
  }
}

// --- Labs catalogue ------------------------------------------------------
const labPages = new Set();
for (const lab of LABS) {
  if (labPages.has(lab.page)) fail(`labs/catalog.mjs: duplicate lab page "${lab.page}"`);
  labPages.add(lab.page);
  if (!fs.existsSync(path.join(root, lab.page))) fail(`labs/catalog.mjs: "${lab.slug}" page does not exist: ${lab.page}`);
  if (!lab.sourceFiles || !lab.sourceFiles.length) fail(`labs/catalog.mjs: "${lab.slug}" has no sourceFiles`);
  if (!lab.sourceFiles.some(file => file.primary)) fail(`labs/catalog.mjs: "${lab.slug}" has no primary source file`);
  for (const file of lab.sourceFiles || []) {
    const resolved = path.resolve(root, file.path);
    if (!resolved.startsWith(root)) fail(`labs/catalog.mjs: "${lab.slug}" source path escapes repository root: ${file.path}`);
    if (!fs.existsSync(path.join(root, file.path))) fail(`labs/catalog.mjs: "${lab.slug}" source file does not exist: ${file.path}`);
  }
  if (!lab.runCommands || !lab.runCommands.length) fail(`labs/catalog.mjs: "${lab.slug}" has no runCommands`);
}

// Every maintained lab directory (one with its own index.html) must be catalogued —
// mirrors the entries/EXPLICIT_ARCHIVED_PATHS completeness check in maintain-gh-pages.mjs,
// so a new lab can't quietly ship without an implementation viewer.
const labsDir = path.join(root, "labs");
for (const item of fs.readdirSync(labsDir, {withFileTypes: true})) {
  if (!item.isDirectory()) continue;
  const page = `labs/${item.name}/index.html`;
  if (fs.existsSync(path.join(root, page)) && !labPages.has(page)) {
    fail(`labs/catalog.mjs: labs/${item.name}/ has an index.html but no catalogue entry`);
  }
}

// Finds the <section id="anchor" ...> ... matching </section>, correctly
// skipping past any nested <section> (the embedded source viewer is itself a
// <section>), instead of a naive non-greedy regex that would stop at the
// first </section> it meets — which is the *inner* one.
function extractSection(html, anchorId) {
  const openTag = new RegExp(`<section\\b[^>]*\\bid=["']${anchorId}["'][^>]*>`);
  const openMatch = openTag.exec(html);
  if (!openMatch) return null;
  const tagRe = /<\/?section\b[^>]*>/gi;
  tagRe.lastIndex = openMatch.index;
  let depth = 0;
  let match;
  while ((match = tagRe.exec(html))) {
    depth += match[0].startsWith("</") ? -1 : 1;
    if (depth === 0) return html.slice(openMatch.index + openMatch[0].length, match.index);
  }
  return null;
}

// --- Generated page structure: source viewer must precede explanation ---
for (const category of SCRIPT_CATEGORIES) {
  const file = path.join(root, "scripts", category.slug, "index.html");
  if (!fs.existsSync(file)) continue;
  const html = fs.readFileSync(file, "utf8");
  const scripts = SCRIPTS.filter(script => script.category === category.slug);
  if (!scripts.length) continue;
  for (const script of scripts) {
    const section = extractSection(html, script.slug);
    if (section == null) { fail(`scripts/${category.slug}/: no <section id="${script.slug}"> found`); continue; }
    const viewerIndex = section.indexOf("docs-source-viewer");
    const whatItDoesIndex = section.indexOf("What it does");
    if (viewerIndex === -1) fail(`scripts/${category.slug}/#${script.slug}: no source viewer rendered`);
    if (whatItDoesIndex === -1) fail(`scripts/${category.slug}/#${script.slug}: no "What it does" section`);
    if (viewerIndex !== -1 && whatItDoesIndex !== -1 && viewerIndex > whatItDoesIndex) {
      fail(`scripts/${category.slug}/#${script.slug}: source viewer must render before "What it does", not after`);
    }
    if (section.includes("github.com/jasonachkar/cybersecurity-writeups/blob")) {
      fail(`scripts/${category.slug}/#${script.slug}: still links to GitHub to view source instead of embedding it`);
    }
  }
}

for (const lab of LABS) {
  const file = path.join(root, lab.page);
  if (!fs.existsSync(file)) continue;
  const html = fs.readFileSync(file, "utf8");
  const viewerIndex = html.indexOf("docs-source-viewer");
  if (viewerIndex === -1) { fail(`${lab.page}: no implementation source viewer rendered`); continue; }
  // "near the top": before the first H2 that isn't the Implementation heading itself,
  // i.e. within the first couple of headings, not appended after a long explanation.
  const headingMatches = [...html.matchAll(/<h2\b[^>]*id=["']([^"']+)["']/g)];
  const implementationHeadingIndex = headingMatches.findIndex(match => match[1] === "implementation");
  if (implementationHeadingIndex === -1) fail(`${lab.page}: no "Implementation" heading found`);
  else if (implementationHeadingIndex > 1) fail(`${lab.page}: "Implementation" heading is not near the top (position ${implementationHeadingIndex})`);
}

// --- Search index must never carry a source-code body ---
// Rather than guess at "code-like" keywords (real prose legitimately contains
// words like "package" or a certification page's own inline example may say
// "def" — banning those would be false positives, not a source-viewer leak),
// pull a distinctive, low-collision line straight out of each catalogued
// source file and confirm it is absent from every search document. That
// directly proves *this* code never reached the index, however it's phrased.
const searchIndexPath = path.join(root, "search/search_index.json");
if (fs.existsSync(searchIndexPath)) {
  const search = JSON.parse(fs.readFileSync(searchIndexPath, "utf8"));
  const allText = (search.docs || []).map(doc => doc.text || "").join("\n");
  for (const doc of search.docs || []) {
    if ((doc.text || "").length > 1200) fail(`search index: "${doc.location}" teaser exceeds 1200 characters (${doc.text.length})`);
  }
  const distinctiveLine = source => {
    const lines = source.split("\n").map(line => line.trim());
    // A line with real code punctuation is far less likely to coincidentally
    // appear in hand-written prose than an isolated identifier would be.
    return lines.find(line => line.length > 24 && /[{}();=]/.test(line) && !line.startsWith("//") && !line.startsWith("#"));
  };
  const allSourceFiles = [...SCRIPTS.flatMap(script => script.sourceFiles), ...LABS.flatMap(lab => lab.sourceFiles)];
  for (const file of allSourceFiles) {
    const fullPath = path.join(root, file.path);
    if (!fs.existsSync(fullPath)) continue;
    const line = distinctiveLine(fs.readFileSync(fullPath, "utf8"));
    if (line && allText.includes(line)) {
      fail(`search index: a line from ${file.path} leaked into the search index ("${line.slice(0, 80)}")`);
    }
  }
}

if (errors.length) {
  console.error(`Catalogue validation failed (${errors.length}):`);
  for (const error of errors.slice(0, 200)) console.error(`- ${error}`);
  process.exit(1);
}

console.log(`Catalogue validation passed: ${SCRIPTS.length} scripts across ${SCRIPT_CATEGORIES.length} categories, ${LABS.length} labs, all source paths verified.`);
