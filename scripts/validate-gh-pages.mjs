import fs from "node:fs";
import path from "node:path";
import {gunzipSync} from "node:zlib";
import {fileURLToPath} from "node:url";
import {NAV_INDEX, NAV_LEFTNAV_HREFS, NAV_ORDER, REVIEW_TIMESTAMP, SITE_ORIGIN, entries} from "./site-config.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const errors = [];
const metrics = {
  htmlPages: 0,
  indexablePages: 0,
  archivedPages: 0,
  utilityPages: 0,
  internalLinks: 0,
  fragmentLinks: 0,
  assetLinks: 0,
  jsonFiles: 0,
  tables: 0,
  images: 0
};
const posix = value => value.split(path.sep).join("/");
const fail = (file, message) => errors.push(`${file}: ${message}`);

function listFiles(directory = root) {
  const result = [];
  for (const item of fs.readdirSync(directory, {withFileTypes: true})) {
    if ([".git", "node_modules", ".tools", ".venv", ".idea", "mkdocs-project"].includes(item.name)) continue;
    const full = path.join(directory, item.name);
    if (item.isDirectory()) result.push(...listFiles(full));
    else if (item.isFile()) result.push(posix(path.relative(root, full)));
  }
  return result;
}

function publicUrl(file) {
  if (file === "index.html") return "/";
  if (file === "404.html") return "/404.html";
  return `/${file.replace(/index\.html$/, "")}`;
}

function urlToFile(url) {
  const clean = decodeURIComponent(url.split(/[?#]/)[0]);
  if (clean === "/" || clean === "" || clean === "/.") return "index.html";
  const relative = clean.replace(/^\//, "");
  if (relative.endsWith("/")) return `${relative}index.html`;
  return relative;
}

function attributes(tag) {
  const result = {};
  for (const match of tag.matchAll(/([:\w-]+)\s*=\s*(["'])([\s\S]*?)\2/g)) result[match[1].toLowerCase()] = match[3];
  return result;
}

const allFiles = listFiles();
const htmlFiles = allFiles.filter(file => file.endsWith(".html")).sort();
const fileSet = new Set(allFiles);
const htmlByFile = new Map(htmlFiles.map(file => [file, fs.readFileSync(path.join(root, file), "utf8")]));
const idsByFile = new Map();

let manifest;
let search;
try { manifest = JSON.parse(fs.readFileSync(path.join(root, "content-status.json"), "utf8")); }
catch (error) { errors.push(`content-status.json: ${error.message}`); manifest = {}; }
try { search = JSON.parse(fs.readFileSync(path.join(root, "search/search_index.json"), "utf8")); }
catch (error) { errors.push(`search/search_index.json: ${error.message}`); search = {docs: []}; }

for (const file of htmlFiles) {
  metrics.htmlPages += 1;
  const html = htmlByFile.get(file);
  const url = publicUrl(file);
  const status = manifest[url];
  if (!status) { fail(file, `missing content-status entry for ${url}`); continue; }
  const isUtility = status.status === "site-utility";
  const isArchived = status.status === "archived";
  const indexable = status.indexable === true || (!isArchived && !isUtility && status.indexable !== false);
  if (indexable) metrics.indexablePages += 1;
  else if (isArchived) metrics.archivedPages += 1;
  else metrics.utilityPages = (metrics.utilityPages || 0) + 1;

  if (!Array.isArray(status.limitations) || status.limitations.length === 0) fail(file, "status limitations are empty");
  if (!Number.isInteger(status.reviewIntervalDays) || status.reviewIntervalDays < 1) fail(file, "invalid review interval");
  if (!isUtility) {
    if (!Array.isArray(status.evidence) || status.evidence.length === 0) fail(file, "status evidence is empty");
  } else if (!Array.isArray(status.evidence)) {
    fail(file, "status evidence must be an array for site-utility pages");
  }

  const titleCount = (html.match(/<title\b/gi) || []).length;
  const h1Count = (html.match(/<h1\b/gi) || []).length;
  const canonicalTags = [...html.matchAll(/<link\b[^>]*rel=["']canonical["'][^>]*>/gi)];
  const evidenceCount = (html.match(/<aside\b[^>]*class=["'][^"']*content-evidence[^"']*["']/gi) || []).length;
  if (titleCount !== 1) fail(file, `expected one title; found ${titleCount}`);
  if (h1Count !== 1) fail(file, `expected one H1; found ${h1Count}`);
  if (canonicalTags.length !== 1) fail(file, `expected one canonical; found ${canonicalTags.length}`);
  if (isUtility) {
    if (evidenceCount !== 0) fail(file, `site-utility page must not have evidence blocks; found ${evidenceCount}`);
    if (/archive-notice/i.test(html)) fail(file, "site-utility page must not use archive notice");
    if (/Archived reference/i.test(html)) fail(file, "site-utility page must not claim archived reference content");
    if (file === "404.html") {
      if (!/<h1\b[^>]*>\s*Page not found\s*<\/h1>/i.test(html)) fail(file, "404 H1 must be exactly 'Page not found'");
      if (!/Go to the homepage/i.test(html)) fail(file, "404 page missing homepage action");
      if (!/evidence registry/i.test(html)) fail(file, "404 page missing evidence registry action");
    }
  } else if (evidenceCount !== 1) {
    fail(file, `expected one server-rendered evidence block; found ${evidenceCount}`);
  }
  if ((html.match(/<!-- docs-left-nav:start -->/g) || []).length !== 1) fail(file, "missing or duplicate left navigation");
  if ((html.match(/<!-- docs-footer:start -->/g) || []).length !== 1) fail(file, "missing or duplicate provenance footer");
  if (/portfolio-nav|md-sidebar--primary/.test(html)) fail(file, "legacy duplicate navigation chrome remains");
  if (!/class=["']md-skip["']/.test(html)) fail(file, "skip link is missing");
  if (!/name=["']author["'][^>]*content=["']Jason Achkar Diab["']/.test(html)) fail(file, "correct author metadata is missing");
  if (!/css\/portfolio\.css/.test(html)) fail(file, "portfolio stylesheet is missing");

  // Footer: Material's original copyright block must be removed from the shipped DOM
  // (not merely hidden with CSS), leaving exactly one footer and one visible copyright.
  if (/md-footer-meta/.test(html)) fail(file, "legacy Material footer-meta block remains (duplicate footer)");
  const footerTagCount = (html.match(/<footer\b[^>]*class=["'][^"']*\bmd-footer\b[^"']*["']/gi) || []).length;
  if (footerTagCount !== 1) fail(file, `expected exactly one <footer class="md-footer">; found ${footerTagCount}`);
  const copyrightCount = (html.match(/docs-footer__copyright/g) || []).length;
  if (copyrightCount !== 1) fail(file, `expected exactly one visible copyright line; found ${copyrightCount}`);

  // TOC: the legacy single-marker/details component must be gone, and the desktop
  // (outside the article) and inline (inside the article) presentations — generated
  // together from the same heading data — must appear together or not at all.
  if (/<!-- docs-toc:start -->|<!-- docs-toc:end -->/.test(html)) fail(file, "legacy single-TOC docs-toc marker remains");
  if (/class=["'][^"']*\barticle-toc\b/.test(html)) fail(file, "legacy .article-toc class remains");
  const desktopTocCount = (html.match(/<!-- docs-desktop-toc:start -->/g) || []).length;
  const inlineTocCount = (html.match(/<!-- docs-inline-toc:start -->/g) || []).length;
  if (desktopTocCount > 1) fail(file, `duplicate desktop TOC; found ${desktopTocCount}`);
  if (inlineTocCount > 1) fail(file, `duplicate inline TOC; found ${inlineTocCount}`);
  if (desktopTocCount !== inlineTocCount) {
    fail(file, `desktop TOC (${desktopTocCount}) and inline TOC (${inlineTocCount}) must be generated together or both omitted`);
  }

  // Documentation-shell invariants: one left nav (every page), breadcrumbs/prev-next
  // only for pages the central NAV_TREE actually knows about, and no orphaned aria-current.
  const ariaCurrentMatches = [...html.matchAll(/<a\b[^>]*\baria-current=["']page["'][^>]*href=["']([^"']+)["']/gi)]
    .concat([...html.matchAll(/<a\b[^>]*href=["']([^"']+)["'][^>]*\baria-current=["']page["']/gi)]);
  if (isUtility || isArchived) {
    if (ariaCurrentMatches.length) fail(file, "site-utility/archived page must not mark a left-nav item as current");
  } else if (NAV_LEFTNAV_HREFS.has(url)) {
    if (ariaCurrentMatches.length !== 1) fail(file, `expected exactly one aria-current="page" left-nav link; found ${ariaCurrentMatches.length}`);
    else if (ariaCurrentMatches[0][1] !== url) fail(file, `aria-current left-nav link ${ariaCurrentMatches[0][1]} does not match page URL ${url}`);
  } else if (ariaCurrentMatches.length) {
    fail(file, "aria-current left-nav link present for a page with no left-nav leaf");
  }
  const breadcrumbCount = (html.match(/<!-- docs-breadcrumbs:start -->/g) || []).length;
  if (NAV_INDEX.has(url)) {
    if (breadcrumbCount !== 1) fail(file, `expected one breadcrumb trail; found ${breadcrumbCount}`);
  } else if (breadcrumbCount !== 0) {
    fail(file, "unexpected breadcrumb trail on a page outside the navigation tree");
  }
  for (const match of html.matchAll(/<!-- docs-prevnext:start -->[\s\S]*?<!-- docs-prevnext:end -->/g)) {
    for (const link of match[0].matchAll(/class="docs-prevnext__link[^"]*"\s+href=["']([^"']+)["']/g)) {
      const target = link[1];
      const targetStatus = manifest[target]?.status;
      if (!NAV_INDEX.has(target) || targetStatus === "archived") fail(file, `prev/next points at a non-navigable page: ${target}`);
    }
  }

  const canonical = canonicalTags[0] ? attributes(canonicalTags[0][0]).href : "";
  if (!canonical.startsWith(`${SITE_ORIGIN}/`) && canonical !== `${SITE_ORIGIN}/`) fail(file, `invalid canonical ${canonical}`);
  const robotsTag = html.match(/<meta\b[^>]*name=["']robots["'][^>]*>/i)?.[0] || "";
  const robots = attributes(robotsTag).content || "";
  if (indexable && /noindex/i.test(robots)) fail(file, "indexable page has noindex");
  if (!indexable && !/noindex/i.test(robots)) fail(file, "non-indexable page lacks noindex");
  if (indexable && /requires-review/i.test(html.match(/<article\b[^>]*>[\s\S]*?<\/article>/i)?.[0] || "")) fail(file, "indexable article exposes requires-review content");
  if (/Draft deployment review/i.test(html)) fail(file, "stale 'Draft deployment review' wording remains");
  if (/awaiting the merge of PR #5/i.test(html)) fail(file, "stale awaiting-merge wording remains");

  const ids = [...html.matchAll(/\sid=["']([^"']+)["']/gi)].map(match => match[1]);
  idsByFile.set(file, new Set(ids));
  const duplicateIds = ids.filter((id, index) => ids.indexOf(id) !== index);
  if (duplicateIds.length) fail(file, `duplicate IDs: ${[...new Set(duplicateIds)].join(", ")}`);

  const headings = [...html.matchAll(/<h([1-6])\b/gi)].map(match => Number(match[1]));
  for (let index = 1; index < headings.length; index += 1) {
    if (headings[index] > headings[index - 1] + 1) fail(file, `heading level jumps H${headings[index - 1]} to H${headings[index]}`);
  }

  for (const match of html.matchAll(/<img\b[^>]*>/gi)) {
    metrics.images += 1;
    const attrs = attributes(match[0]);
    if (!("alt" in attrs)) fail(file, `image lacks alt: ${match[0].slice(0, 100)}`);
  }
  for (const match of html.matchAll(/<table\b[\s\S]*?<\/table>/gi)) {
    metrics.tables += 1;
    if (!/<th\b/i.test(match[0])) fail(file, "table has no header cells");
  }
  for (const match of html.matchAll(/<a\b[^>]*target=["']_blank["'][^>]*>/gi)) {
    const rel = attributes(match[0]).rel || "";
    if (!/\bnoopener\b/.test(rel) || !/\bnoreferrer\b/.test(rel)) fail(file, "target=_blank link lacks noopener noreferrer");
  }
  if (/(?:src|href)=["']http:\/\//i.test(html)) fail(file, "mixed-content resource or link");
  if (/<script\b[^>]*src=["']https?:\/\//i.test(html)) fail(file, "remote JavaScript dependency");
  for (const match of html.matchAll(/<script\b[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi)) {
    try { JSON.parse(match[1]); } catch (error) { fail(file, `invalid JSON-LD: ${error.message}`); }
  }
}

function resolveLocal(fromFile, reference) {
  const [pathPart] = reference.split(/[?#]/);
  if (!pathPart) return fromFile;
  if (pathPart.startsWith("/")) return urlToFile(pathPart);
  const normalized = path.posix.normalize(path.posix.join(path.posix.dirname(fromFile), decodeURIComponent(pathPart)));
  if (normalized === ".") return "index.html";
  if (fileSet.has(normalized)) return normalized;
  if (fileSet.has(`${normalized}/index.html`)) return `${normalized}/index.html`;
  if (normalized.endsWith("/")) return `${normalized}index.html`;
  return normalized;
}

for (const file of htmlFiles) {
  const html = htmlByFile.get(file);
  for (const match of html.matchAll(/<(a|link|script|img)\b[^>]*(?:href|src)=["']([^"']+)["'][^>]*>/gi)) {
    const tag = match[1].toLowerCase();
    const reference = match[2];
    if (/^(?:https?:|mailto:|tel:|data:|javascript:)/i.test(reference)) continue;
    const target = resolveLocal(file, reference);
    const isAsset = tag !== "a";
    if (isAsset) metrics.assetLinks += 1; else metrics.internalLinks += 1;
    if (!fileSet.has(target)) { fail(file, `missing local target ${reference} -> ${target}`); continue; }
    const fragment = reference.includes("#") ? decodeURIComponent(reference.slice(reference.indexOf("#") + 1)) : "";
    if (fragment) {
      metrics.fragmentLinks += 1;
      if (!idsByFile.get(target)?.has(fragment)) fail(file, `missing fragment ${reference}`);
    }
  }
}

const manifestUrls = new Set(Object.keys(manifest));
const htmlUrls = new Set(htmlFiles.map(publicUrl));
for (const url of htmlUrls) if (!manifestUrls.has(url)) errors.push(`content-status.json: missing ${url}`);
for (const url of manifestUrls) if (!htmlUrls.has(url)) errors.push(`content-status.json: non-existent page ${url}`);

const indexableUrls = new Set(
  [...manifestUrls].filter((url) => {
    const item = manifest[url];
    if (!item) return false;
    if (item.indexable === false) return false;
    if (item.status === "archived" || item.status === "site-utility") return false;
    return item.indexable === true || item.status !== "archived";
  })
);
const sitemapText = fs.readFileSync(path.join(root, "sitemap.xml"), "utf8");
const sitemapUrls = new Set([...sitemapText.matchAll(/<loc>([^<]+)<\/loc>/g)].map(match => match[1].replace(SITE_ORIGIN, "")));
for (const url of indexableUrls) if (!sitemapUrls.has(url)) errors.push(`sitemap.xml: missing ${url}`);
for (const url of sitemapUrls) if (!indexableUrls.has(url)) errors.push(`sitemap.xml: includes non-indexable ${url}`);
const inflated = gunzipSync(fs.readFileSync(path.join(root, "sitemap.xml.gz"))).toString("utf8");
if (inflated !== sitemapText) errors.push("sitemap.xml.gz: content differs from sitemap.xml");

const searchUrls = new Set((search.docs || []).map(doc => publicUrl(doc.location ? `${doc.location}index.html` : "index.html")));
for (const url of indexableUrls) if (!searchUrls.has(url)) errors.push(`search index: missing ${url}`);
for (const url of searchUrls) if (!indexableUrls.has(url)) errors.push(`search index: includes non-indexable ${url}`);

for (const file of allFiles.filter(file => file.endsWith(".json"))) {
  metrics.jsonFiles += 1;
  try { JSON.parse(fs.readFileSync(path.join(root, file), "utf8")); }
  catch (error) { fail(file, `invalid JSON: ${error.message}`); }
}

try {
  const meta = JSON.parse(fs.readFileSync(path.join(root, "site-meta.json"), "utf8"));
  if (meta.site !== SITE_ORIGIN || meta.publicationTarget !== "gh-pages" || meta.reviewBranch !== "codex/validated-gh-pages-deployment" || meta.pullRequest !== 5) errors.push("site-meta.json: incorrect deployment review provenance");
  if ("sourceCommit" in meta || "sourceBranch" in meta) errors.push("site-meta.json: misleading self-referential source field remains");
} catch (error) { errors.push(`site-meta.json: ${error.message}`); }
if (fs.readFileSync(path.join(root, "CNAME"), "utf8").trim() !== "docs.jasonachkardiab.com") errors.push("CNAME: canonical domain changed");
if (!fs.existsSync(path.join(root, ".nojekyll"))) errors.push(".nojekyll: missing");
for (const file of entries.keys()) if (!htmlByFile.has(file)) errors.push(`site-config: configured page missing ${file}`);

const report = {timestamp: REVIEW_TIMESTAMP, status: errors.length ? "failed" : "passed", metrics, errors};
fs.mkdirSync(path.join(root, "qa"), {recursive: true});
fs.writeFileSync(path.join(root, "qa/validation-report.json"), `${JSON.stringify(report, null, 2)}\n`);

if (errors.length) {
  console.error(`Static-site validation failed with ${errors.length} error(s):`);
  for (const error of errors.slice(0, 200)) console.error(`- ${error}`);
  if (errors.length > 200) console.error(`- ... ${errors.length - 200} more`);
  process.exit(1);
}

console.log(`Static-site validation passed: ${metrics.htmlPages} HTML pages (${metrics.indexablePages} indexable, ${metrics.archivedPages} archived).`);
console.log(`Checked ${metrics.internalLinks} internal links, ${metrics.fragmentLinks} fragments, ${metrics.assetLinks} assets, ${metrics.tables} tables, ${metrics.images} images, and ${metrics.jsonFiles} JSON files.`);
console.log(`Sitemap/search/status sets are equal at ${indexableUrls.size} indexable URLs; gzip sitemap is byte-consistent after decompression.`);
