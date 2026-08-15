"use strict";

const fs = require("node:fs");
const path = require("node:path");
const YAML = require("yaml");
const { ROOT, parseDocument } = require("./content-lib");

const REPOSITORY = "https://github.com/jasonachkar/cybersecurity-writeups";
const DOMAIN_ORDER = ["cloud-security", "appsec", "devsecops", "threat-intel"];
const DOMAINS = Object.freeze({
  "cloud-security": { title: "Cloud Security", description: "Identity, network, platform, detection, and cloud control-plane architecture." },
  appsec: { title: "Application Security", description: "Authorization, tenant isolation, identity protocols, APIs, and runtime boundaries." },
  devsecops: { title: "DevSecOps", description: "CI/CD trust, infrastructure policy, software supply chain, and secrets engineering." },
  "threat-intel": { title: "Threat Intelligence", description: "Evidence-backed attack paths, incident chronology, and defensive lessons." },
});
const STATUS_LABELS = Object.freeze({
  verified: "Verified",
  "partially-verified": "Partially verified",
  "requires-review": "Requires review",
  historical: "Historical",
  tested: "Tested",
  "partially-tested": "Partially tested",
  illustrative: "Illustrative",
  pseudocode: "Pseudocode",
  "primary-sources-reviewed": "Primary sources reviewed",
  "mixed-sources": "Mixed sources",
});
const STATUS_DESCRIPTIONS = Object.freeze({
  verified: "Material current-state claims were checked against the listed evidence and important runnable examples are labeled.",
  "partially-verified": "The article has reviewed evidence, but one or more documented validation gaps remain.",
  "requires-review": "The material has not completed the repository's current evidence review.",
  historical: "The material is retained for historical context and is not current guidance.",
  tested: "The bounded implementation and its declared negative cases run in the repository test suite.",
  "partially-tested": "Some controls are backed by executable tests, but the complete architecture is not production-validated.",
  illustrative: "Examples communicate a design and have not been exercised as a complete implementation.",
  pseudocode: "The example is explanatory pseudocode rather than runnable implementation.",
});
const PRIMARY_RESEARCH = /^(appsec|cloud-security|devsecops|threat-intel)\/[^/]+\.md$/;
const RELATION_TYPES = Object.freeze({ research: "research", labs: "lab", scripts: "script" });

function fail(message) { throw new Error(`docs catalog: ${message}`); }
function rel(file) { return path.relative(ROOT, file).replace(/\\/g, "/"); }
function readYaml(file) { return YAML.parse(fs.readFileSync(file, "utf8")); }
function assertString(value, label) {
  if (typeof value !== "string" || !value.trim()) fail(`${label} must be a nonempty string`);
}
function assertOrder(value, label) {
  if (!Number.isInteger(value) || value < 1) fail(`${label} must be a positive integer`);
}
function safeSourcePath(value, label) {
  assertString(value, label);
  const normalized = path.posix.normalize(value);
  if (normalized.startsWith("../") || normalized.startsWith("/") || normalized !== value.replace(/\\/g, "/")) {
    fail(`${label} must be a normalized repository-relative path`);
  }
  const absolute = path.resolve(ROOT, normalized);
  if (!absolute.startsWith(`${ROOT}${path.sep}`) || !fs.existsSync(absolute) || !fs.statSync(absolute).isFile()) {
    fail(`${label} does not resolve to a regular repository file: ${value}`);
  }
  return normalized;
}

function firstHeading(body) {
  const match = body.match(/^#\s+(.+)$/m);
  return match ? match[1].replace(/\s+#+\s*$/, "").trim() : "";
}

function headingId(value) {
  return String(value).toLowerCase().normalize("NFKD").replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9\s-]/g, "").trim().replace(/[\s-]+/g, "-");
}

function derivedReadingTime(body) {
  const prose = body
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/https?:\/\/\S+/g, " ")
    .replace(/[`*_>#|\[\](){}~-]/g, " ");
  const words = prose.match(/[\p{L}\p{N}][\p{L}\p{N}'’-]*/gu) || [];
  return Math.max(1, Math.ceil(words.length / 225));
}

function commonItem({ kind, id, title, navTitle, order, domain, sourcePath, url, metadata, body }) {
  assertString(id, `${sourcePath}: id`);
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(id)) fail(`${sourcePath}: invalid id ${id}`);
  assertString(title, `${sourcePath}: title`);
  assertString(navTitle, `${sourcePath}: navTitle`);
  assertOrder(order, `${sourcePath}: order`);
  if (!DOMAINS[domain]) fail(`${sourcePath}: unsupported domain ${domain}`);
  const heading = firstHeading(body);
  if (heading !== title) fail(`${sourcePath}: H1 ${JSON.stringify(heading)} must match title ${JSON.stringify(title)}`);
  return {
    kind, id, title, navTitle, order, domain, domainLabel: DOMAINS[domain].title,
    sourcePath, url, headingId: headingId(title), summary: metadata.summary || "", keyTakeaway: metadata.keyTakeaway || "",
    readingTime: Number.isInteger(metadata.readingTime) ? metadata.readingTime : derivedReadingTime(body),
    related: { research: [], labs: [], scripts: [] }, declaredRelated: metadata.related || {},
    github: {
      view: `${REPOSITORY}/blob/main/${sourcePath}`,
      edit: `${REPOSITORY}/edit/main/${sourcePath}`,
      raw: `https://raw.githubusercontent.com/jasonachkar/cybersecurity-writeups/main/${sourcePath}`,
    },
  };
}

function loadResearch() {
  const result = [];
  for (const domain of DOMAIN_ORDER) {
    const directory = path.join(ROOT, domain);
    for (const name of fs.readdirSync(directory).filter(item => item.endsWith(".md") && item !== "index.md").sort()) {
      const absolute = path.join(directory, name);
      const sourcePath = rel(absolute);
      if (!PRIMARY_RESEARCH.test(sourcePath)) continue;
      const document = parseDocument(absolute);
      if (/<span id="__span-|<div class="language-[^"]+ highlight">/.test(document.body)) {
        fail(`${sourcePath}: rendered syntax-highlighting HTML must be restored to a fenced code block`);
      }
      const metadata = document.metadata || {};
      const id = metadata.id;
      const item = commonItem({
        kind: "research", id, title: metadata.title, navTitle: metadata.navTitle,
        order: metadata.order, domain, sourcePath, url: `/${domain}/${name.slice(0, -3)}/`,
        metadata, body: document.body,
      });
      Object.assign(item, {
        date: metadata.date,
        lastReviewed: metadata.lastReviewed,
        reviewStatus: metadata.reviewStatus,
        reviewLabel: STATUS_LABELS[metadata.reviewStatus] || metadata.reviewStatus,
        reviewDescription: STATUS_DESCRIPTIONS[metadata.reviewStatus] || "",
        implementationStatus: metadata.implementationStatus,
        implementationLabel: STATUS_LABELS[metadata.implementationStatus] || metadata.implementationStatus,
        implementationDescription: STATUS_DESCRIPTIONS[metadata.implementationStatus] || "",
        sourceQuality: metadata.sourceQuality,
        sourceQualityLabel: STATUS_LABELS[metadata.sourceQuality] || metadata.sourceQuality,
        validatedAgainst: metadata.validatedAgainst || [],
        featured: metadata.featured === true,
        featuredOrder: metadata.featuredOrder,
      });
      if (item.featured) {
        assertOrder(item.featuredOrder, `${sourcePath}: featuredOrder`);
        assertString(item.summary, `${sourcePath}: featured summary`);
      }
      result.push(item);
    }
  }
  return result;
}

function loadLabs() {
  const result = [];
  const root = path.join(ROOT, "labs");
  for (const entry of fs.readdirSync(root, { withFileTypes: true }).filter(item => item.isDirectory()).sort((a, b) => a.name.localeCompare(b.name))) {
    const absolute = path.join(root, entry.name, "README.md");
    if (!fs.existsSync(absolute)) continue;
    const sourcePath = rel(absolute);
    const document = parseDocument(absolute);
    if (/<span id="__span-|<div class="language-[^"]+ highlight">/.test(document.body)) {
      fail(`${sourcePath}: rendered syntax-highlighting HTML must be restored to a fenced code block`);
    }
    const metadata = document.metadata || {};
    const item = commonItem({
      kind: "lab", id: metadata.id, title: metadata.title, navTitle: metadata.navTitle,
      order: metadata.order, domain: metadata.domain, sourcePath, url: `/labs/${entry.name}/`,
      metadata, body: document.body,
    });
    if (!Array.isArray(metadata.sourceFiles) || !metadata.sourceFiles.length) fail(`${sourcePath}: sourceFiles must be nonempty`);
    item.sourceFiles = metadata.sourceFiles.map((file, index) => ({
      ...file,
      path: safeSourcePath(file.path, `${sourcePath}: sourceFiles[${index}].path`),
      primary: file.primary === true || (index === 0 && !metadata.sourceFiles.some(candidate => candidate.primary === true)),
    }));
    item.runCommands = metadata.runCommands || [];
    item.implementationStatus = metadata.implementationStatus;
    item.implementationLabel = STATUS_LABELS[metadata.implementationStatus] || metadata.implementationStatus;
    item.implementationDescription = STATUS_DESCRIPTIONS[metadata.implementationStatus] || "";
    result.push(item);
  }
  return result;
}

function loadScripts() {
  const catalogPath = path.join(ROOT, "site-pages", "scripts", "catalog.yml");
  const payload = readYaml(catalogPath);
  if (payload.schemaVersion !== 1 || !Array.isArray(payload.categories) || !Array.isArray(payload.scripts)) {
    fail("site-pages/scripts/catalog.yml has an unsupported shape");
  }
  const categoryIds = new Set(payload.categories.map(item => item.id));
  const scripts = payload.scripts.map(entry => {
    if (!categoryIds.has(entry.category)) fail(`script ${entry.id}: unknown category ${entry.category}`);
    const domain = entry.category === "application-security" ? "appsec" : entry.category === "threat-intelligence" ? "threat-intel" : entry.category;
    assertString(entry.id, "script id");
    assertString(entry.title, `script ${entry.id}: title`);
    assertOrder(entry.order, `script ${entry.id}: order`);
    const route = `/scripts/${entry.category}/`;
    return {
      kind: "script", id: entry.id, title: entry.title, navTitle: entry.title, order: entry.order,
      domain, domainLabel: DOMAINS[domain].title, category: entry.category, sourcePath: entry.sourceFiles[0].path,
      url: `${route}#${entry.id}`, route, summary: entry.purpose, purpose: entry.purpose, why: entry.why,
      language: entry.language, modifiesState: entry.modifiesState === true, testStatus: entry.testStatus,
      usage: entry.usage, permissions: entry.permissions, tested: entry.tested, limitations: entry.limitations || [],
      sourceFiles: entry.sourceFiles.map((file, index) => ({
        ...file,
        path: safeSourcePath(file.path, `script ${entry.id}: sourceFiles[${index}].path`),
        primary: file.primary === true || (index === 0 && !entry.sourceFiles.some(candidate => candidate.primary === true)),
      })),
      related: { research: [], labs: [], scripts: [] }, declaredRelated: entry.related || {},
      github: {
        view: `${REPOSITORY}/blob/main/${entry.sourceFiles[0].path}`,
        raw: `https://raw.githubusercontent.com/jasonachkar/cybersecurity-writeups/main/${entry.sourceFiles[0].path}`,
      },
    };
  });
  return { categories: payload.categories.sort((a, b) => a.order - b.order), scripts };
}

function connectRelations(items) {
  const byKind = { research: new Map(), lab: new Map(), script: new Map() };
  for (const item of items) {
    if (byKind[item.kind].has(item.id)) fail(`duplicate ${item.kind} id ${item.id}`);
    byKind[item.kind].set(item.id, item);
  }
  for (const item of items) {
    for (const [relationName, targetKind] of Object.entries(RELATION_TYPES)) {
      const ids = item.declaredRelated[relationName] || [];
      if (!Array.isArray(ids) || new Set(ids).size !== ids.length) fail(`${item.sourcePath}: related.${relationName} must contain unique IDs`);
      for (const id of ids) {
        const target = byKind[targetKind].get(id);
        if (!target) fail(`${item.sourcePath}: related.${relationName} references unknown ${id}`);
        if (target === item) fail(`${item.sourcePath}: self relation ${id} is not allowed`);
        if (!item.related[relationName].some(candidate => candidate.id === target.id)) item.related[relationName].push(target);
        const reverseName = item.kind === "lab" ? "labs" : item.kind === "script" ? "scripts" : "research";
        if (!target.related[reverseName].some(candidate => candidate.id === item.id)) target.related[reverseName].push(item);
      }
    }
  }
  for (const item of items) {
    delete item.declaredRelated;
    for (const [name, values] of Object.entries(item.related)) {
      item.related[name] = values
        .sort((a, b) => a.order - b.order || a.title.localeCompare(b.title))
        .map(target => ({
          kind: target.kind,
          id: target.id,
          title: target.title,
          navTitle: target.navTitle,
          url: target.url,
          summary: target.summary,
          domainLabel: target.domainLabel,
          implementationLabel: target.implementationLabel,
        }));
    }
  }
}

function pageMap(research, labs, scripts) {
  const map = {};
  for (const item of research) map[item.sourcePath] = item;
  for (const item of labs) map[`labs/${item.id}/README.md`] = item;
  for (const category of scripts.categories) {
    const source = `site-pages/scripts/${category.id}.md`;
    map[`scripts/${category.id}.md`] = {
      kind: "script-category", id: category.id, title: `${category.title} scripts`,
      headingId: headingId(`${category.title} scripts`), domainLabel: category.title,
      summary: category.description, sourcePath: source, url: `/scripts/${category.id}/`,
      github: {
        view: `${REPOSITORY}/blob/main/${source}`,
        edit: `${REPOSITORY}/edit/main/${source}`,
      },
      scripts: scripts.scripts.filter(item => item.category === category.id),
    };
  }
  return map;
}

function navigation(research, labs, scripts) {
  const researchGroups = DOMAIN_ORDER.map(domain => ({
    title: DOMAINS[domain].title,
    index: `${domain}/index.md`,
    children: research.filter(item => item.domain === domain).sort((a, b) => a.order - b.order).map(item => ({ title: item.navTitle, path: item.sourcePath })),
  }));
  return {
    researchGroups,
    labs: labs.slice().sort((a, b) => a.order - b.order).map(item => ({ title: item.navTitle, path: `labs/${item.id}/README.md` })),
    scriptCategories: scripts.categories.map(category => ({ title: category.title, path: `scripts/${category.id}.md` })),
  };
}

function buildCatalog() {
  const research = loadResearch();
  const labs = loadLabs();
  const scriptData = loadScripts();
  const all = [...research, ...labs, ...scriptData.scripts];
  connectRelations(all);
  const featured = research.filter(item => item.featured).sort((a, b) => a.featuredOrder - b.featuredOrder);
  if (featured.length !== 4) fail(`expected exactly 4 featured research articles, found ${featured.length}`);
  const recent = research.slice().sort((a, b) =>
    String(b.lastReviewed).localeCompare(String(a.lastReviewed)) || String(b.date).localeCompare(String(a.date)) || a.order - b.order || a.title.localeCompare(b.title)
  ).slice(0, 5);
  return {
    schemaVersion: 1,
    repository: REPOSITORY,
    domains: DOMAIN_ORDER.map(id => ({ id, ...DOMAINS[id], count: research.filter(item => item.domain === id).length })),
    research, labs, scriptCategories: scriptData.categories, scripts: scriptData.scripts,
    featured, recent, pageMap: pageMap(research, labs, scriptData), navigation: navigation(research, labs, scriptData),
  };
}

module.exports = {
  DOMAINS, STATUS_DESCRIPTIONS, STATUS_LABELS, buildCatalog, connectRelations,
  derivedReadingTime, navigation, safeSourcePath,
};
