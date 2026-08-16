import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import {HtmlValidate} from "html-validate";
import {createRequire} from "node:module";
import {ROOT, SITE, indexableUrls, lifecycle, outputForUrl, readPage} from "./site-helper.mjs";

const require = createRequire(import.meta.url);
const {buildCatalog} = require("../../scripts/docs-catalog-lib.js");
const catalog = buildCatalog();

test("every lifecycle route exists and archived routes remain noindex", () => {
  for (const [url, item] of Object.entries(lifecycle)) {
    const file = path.join(SITE, outputForUrl(url));
    assert.ok(fs.existsSync(file), `missing preserved route ${url}`);
    if (item.status === "archived") {
      const html = fs.readFileSync(file, "utf8");
      assert.match(html, /name="robots" content="noindex, nofollow"/);
      assert.match(html, /Archived reference/);
    }
  }
});

test("catalog-managed research has canonical metadata, read-only source actions, and no duplicate H1", () => {
  for (const item of catalog.research) {
    const html = readPage(item.url);
    assert.equal((html.match(/<h1\b/g) || []).length, 1, item.url);
    assert.match(html, new RegExp(`<meta name="description" content="${item.summary ? item.summary.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") : "Deep-dive"}`));
    assert.ok(html.includes(`href="${item.github.view}"`), `${item.url}: view source`);
    assert.doesNotMatch(html, /\/edit\/main\//, `${item.url}: editing must not be offered`);
    assert.doesNotMatch(html, />Edit on GitHub</);
    assert.match(html, /class="docs-evidence"/);
    assert.doesNotMatch(html, /<section class="docs-related"[^>]*>\s*<h2[^>]*>Related content<\/h2>\s*<div[^>]*>\s*<\/div>/);
  }
});

test("every research Mermaid fence is emitted as a renderable diagram", () => {
  for (const item of catalog.research) {
    const source = fs.readFileSync(path.join(ROOT, item.sourcePath), "utf8");
    const diagramCount = (source.match(/^```mermaid(?:\s.*)?$/gm) || []).length;
    if (!diagramCount) continue;
    const html = readPage(item.url);
    assert.equal((html.match(/class="mermaid"/g) || []).length, diagramCount, `${item.url}: Mermaid diagram count`);
    assert.match(html, /js\/vendor\/mermaid\.min\.js/, `${item.url}: local Mermaid runtime`);
  }
});

test("homepage, search enrichment, and source viewers derive from the catalog", () => {
  const home = readPage("/");
  assert.equal((home.match(/class="docs-card" href="\/(?:appsec|cloud-security|devsecops|threat-intel)\//g) || []).length, 4);
  assert.match(home, /class="docs-link-arrow" aria-hidden="true">→<\/span>/);
  const recentTitles = [...home.matchAll(/<ol class="docs-recent">([\s\S]*?)<\/ol>/g)][0][1];
  let cursor = -1;
  for (const item of catalog.recent) {
    const next = recentTitles.indexOf(item.navTitle);
    assert.ok(next > cursor, `recent order: ${item.navTitle}`);
    cursor = next;
  }
  const scripts = readPage("/scripts/devsecops/");
  assert.match(scripts, /data-search-exclude/);
  assert.match(scripts, /blob\/main\/scripts\/validate-kyverno-policy.py/);
  assert.match(scripts, /id="source-kyverno-policy-schema-check-0-L1"/);
  assert.match(scripts, /href="#source-kyverno-policy-schema-check-0-L1"/);
  const search = JSON.parse(fs.readFileSync(path.join(SITE, "search/search_index.json"), "utf8"));
  const ai = search.docs.find(record => record.location === "appsec/ai-agent-security/");
  assert.match(ai.text, /Application Security · Research/);
  assert.match(ai.text, /External authorization/);
  const devsecops = search.docs.find(record => record.location === "scripts/devsecops/");
  assert.doesNotMatch(devsecops.text, /import jsonschema/);
});

test("generated indexable HTML passes structural validation", async () => {
  const validator = new HtmlValidate({
    extends: ["html-validate:recommended"],
    rules: {
      "doctype-style": "off", "no-trailing-whitespace": "off", "long-title": "off",
      "void-style": "off", "no-inline-style": "off", "valid-id": ["error", {relaxed: true}],
      "input-attributes": "off", "valid-autocomplete": "off", "wcag/h32": "off",
      "attribute-empty-style": "off",
      // Material emits several responsive copies of navigation landmarks. Their
      // runtime visibility and accessible names are checked with axe-core.
      "unique-landmark": "off",
    },
  });
  const files = indexableUrls.map(url => path.join(SITE, outputForUrl(url)));
  const report = await validator.validateMultipleFiles(files);
  assert.equal(report.valid, true, report.results.flatMap(result => result.messages.map(message => `${path.relative(ROOT, result.filePath)}:${message.line} ${message.ruleId}: ${message.message}`)).slice(0, 30).join("\n"));
});

test("the static artifact is self-contained and publishable", () => {
  assert.ok(fs.existsSync(path.join(SITE, ".nojekyll")));
  assert.equal(fs.readFileSync(path.join(SITE, "CNAME"), "utf8").trim(), "docs.jasonachkardiab.com");
  assert.doesNotMatch(readPage("/"), /fonts\.(?:googleapis|gstatic)\.com/);
  assert.ok(fs.existsSync(path.join(SITE, "js/vendor/mermaid.min.js")));
  const about = readPage("/about/");
  assert.match(about, /class="mermaid"/);
  assert.match(about, /data-diagram-label="Canonical documentation publishing flow"/);
  assert.match(about, /js\/vendor\/mermaid\.min\.js/);
  assert.doesNotMatch(about, /(?:cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com).*mermaid/i);
  assert.doesNotMatch(readPage("/"), /js\/vendor\/mermaid\.min\.js/);
});
