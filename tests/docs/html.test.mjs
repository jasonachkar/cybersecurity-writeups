import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test, {after, before} from "node:test";
import {spawnSync} from "node:child_process";
import {chromium} from "playwright";
import {HtmlValidate} from "html-validate";
import {createRequire} from "node:module";
import {ROOT, SITE, indexableUrls, lifecycle, outputForUrl, readPage, writeReport} from "./site-helper.mjs";
import {rawMarkdownInArticle, scriptCategories, scriptLinks, studyNoteRoutes, studyGuideUrl} from "./markdown-content.mjs";

const require = createRequire(import.meta.url);
const {buildCatalog} = require("../../scripts/docs-catalog-lib.js");
const catalog = buildCatalog();
let browser;
let domContext;
before(async () => {
  browser = await chromium.launch();
  // Parse the saved build output without any client-side repair or rendering.
  domContext = await browser.newContext({javaScriptEnabled: false});
});
after(async () => { await browser?.close(); });

async function withArticle(url, check) {
  const page = await domContext.newPage();
  try {
    await page.setContent(readPage(url));
    const article = page.locator("article.md-content__inner");
    assert.equal(await article.count(), 1, url);
    await check(article);
  } finally { await page.close(); }
}

test("scripts index emits category headings, links and separate script list items", async () => {
  await withArticle("/scripts/", async article => {
    assert.equal(await article.locator("h1").count(), 1);
    assert.equal(await article.locator("h2").count(), 4);
    for (const {title, url, id} of scriptCategories) {
      assert.equal(await article.getByRole("heading", {level: 2, name: new RegExp(`^${title}\\s*¶?$`)}).count(), 1);
      assert.equal(await article.locator(`h2[id='${id}']`).count(), 1);
      assert.equal(await article.getByRole("link", {name: `Open the ${title} category`, exact: true}).getAttribute("href"), url);
    }
    for (const [title, href] of scriptLinks) {
      assert.equal(await article.getByRole("link", {name: title, exact: true}).getAttribute("href"), href);
      assert.equal(await article.locator(`li > a[href='${href}']`).count(), 1);
    }
    const validators = article.locator("ul:has(> li > a[href$='#kyverno-policy-schema-check'])");
    assert.equal(await validators.locator(":scope > li").count(), 2);
    assert.equal(await article.locator("li > .docs-script-meta").count(), 5);
    assert.deepEqual(await article.evaluate(rawMarkdownInArticle), []);
  });
});

for (const url of studyNoteRoutes) {
  test(`${url} renders its semantic aside as Markdown`, async () => {
    await withArticle(url, async article => {
      const aside = article.locator("aside.study-currency[aria-label='Official-owner check']");
      assert.equal(await aside.count(), 1);
      assert.equal(await aside.locator("strong").count(), 2);
      assert.equal(await aside.locator("strong").first().textContent(), "Official-owner check");
      assert.equal(await aside.locator("strong").nth(1).textContent(), "2026-05-13");
      assert.equal(await aside.getByRole("link", {name: "Official SC-500 study guide", exact: true}).getAttribute("href"), studyGuideUrl);
      assert.equal(await aside.locator("p").count(), 2);
      assert.equal(await aside.getAttribute("markdown"), null);
      assert.deepEqual(await article.evaluate(rawMarkdownInArticle), []);
    });
  });
}

test("all built article DOM is free of unintended Markdown outside examples", async () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(SITE, "docs-build-manifest.json"), "utf8"));
  const routes = new Map(manifest.routes.map(route => [route.output, route]));
  function htmlFiles(directory) {
    return fs.readdirSync(directory, {withFileTypes: true}).flatMap(entry => {
      const file = path.join(directory, entry.name);
      return entry.isDirectory() ? htmlFiles(file) : entry.name.endsWith(".html") ? [file] : [];
    });
  }
  const results = [];
  const page = await domContext.newPage();
  try {
    for (const file of htmlFiles(SITE)) {
      await page.setContent(fs.readFileSync(file, "utf8"));
      const output = path.relative(SITE, file).split(path.sep).join("/");
      const article = page.locator("article.md-content__inner");
      assert.equal(await article.count(), 1, output);
      results.push({output, source: routes.get(output)?.source ?? null, findings: await article.evaluate(rawMarkdownInArticle)});
    }
  } finally { await page.close(); }
  writeReport("markdown-rendering-dom.json", {pages: results.length, results});
  const failures = results.filter(result => result.findings.length);
  assert.deepEqual(failures, [], JSON.stringify(failures, null, 2));
});

test("the installed renderer reproduces HTML-block leakage and validates both fixes", async () => {
  const fixture = fs.readFileSync(path.join(ROOT, "tests/docs/fixtures/markdown-in-html.md"), "utf8");
  const fixed = fixture.replace(/^<\/?section>\n/gm, "").replace('<aside class="study-currency"', '<aside markdown="1" class="study-currency"');
  const render = spawnSync(path.join(ROOT, ".venv/bin/python"), ["-c", `
import json, sys, markdown
from mkdocs.config import load_config
config = load_config(config_file="mkdocs-project/mkdocs.yml")
original, fixed = json.load(sys.stdin)
def render(source, extensions):
    return markdown.Markdown(extensions=extensions, extension_configs=config.mdx_configs).convert(source)
extensions = config.markdown_extensions
without = [extension for extension in extensions if extension != "md_in_html"]
json.dump({"original": render(original, extensions), "fixed": render(fixed, extensions), "withoutExtension": render(fixed, without)}, sys.stdout)
`], {cwd: ROOT, input: JSON.stringify([fixture, fixed]), encoding: "utf8"});
  assert.equal(render.status, 0, render.stderr || render.error?.message);
  const output = JSON.parse(render.stdout);
  const page = await domContext.newPage();
  try {
    await page.setContent(`<article>${output.original}</article>`);
    assert.equal(await page.locator("article h2").count(), 0, "enabling the extension alone must not parse unmarked wrappers");
    assert.ok((await page.locator("article").evaluate(rawMarkdownInArticle)).some(item => item.kind === "heading"));
    await page.setContent(`<article>${output.withoutExtension}</article>`);
    assert.equal(await page.locator("article h2").count(), 1, "ordinary Markdown needs no HTML extension");
    assert.equal(await page.locator("aside a").count(), 0, "the attribute alone is insufficient");
    await page.setContent(`<article>${output.fixed}</article>`);
    assert.equal(await page.getByRole("heading", {level: 2, name: /^Cloud Security\s*¶?$/}).count(), 1);
    assert.equal(await page.locator("li > a").count(), 2);
    assert.equal(await page.locator("aside a").getAttribute("href"), studyGuideUrl);
    assert.equal(await page.locator("aside strong").textContent(), "Official-owner check");
    assert.deepEqual(await page.locator("article").evaluate(rawMarkdownInArticle), []);
  } finally { await page.close(); }
});

test("the DOM guard detects raw blocks and excludes intentional examples and semantic numbering", async () => {
  const page = await domContext.newPage();
  try {
    for (const tag of ["section", "div", "article", "details", "aside"]) {
      await page.setContent(`<article id="content"><${tag}>\n## Leaked heading\n[Leaked link](/scripts/)\n- Leaked list\n\n\`\`\`markdown\n| Broken | Table |\n**Unparsed emphasis**\n</${tag}></article>`);
      assert.deepEqual((await page.locator("#content").evaluate(rawMarkdownInArticle)).map(item => item.kind).sort(), ["heading", "link", "list", "fence", "table", "emphasis"].sort(), tag);
    }
    await page.setContent(`<article>
      <pre>## Heading\n[Link](/scripts/)\n- List\n\`\`\`markdown</pre>
      <p><code>[Inline example](/scripts/)</code></p>
      <script type="text/plain">## Script example</script><style>/* ## Style example */</style>
      <div data-markdown-example="Demonstrates Markdown heading and link syntax">## Heading\n[Link](/scripts/)</div>
      <h2>1. Numbered heading</h2><table><tr><td>1. Phase label</td></tr></table>
      <ul><li><code>STATUS</code> - explanatory prose</li></ul>
    </article>`);
    assert.deepEqual(await page.locator("article").evaluate(rawMarkdownInArticle), []);
  } finally { await page.close(); }
});

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
    assert.doesNotMatch(html, /class="docs-evidence"/);
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
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(SITE, "content-status.json"), "utf8")), lifecycle);
  const about = readPage("/about/");
  assert.match(about, /class="mermaid"/);
  assert.match(about, /data-diagram-label="Canonical documentation publishing flow"/);
  assert.match(about, /js\/vendor\/mermaid\.min\.js/);
  assert.doesNotMatch(about, /(?:cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com).*mermaid/i);
  assert.doesNotMatch(readPage("/"), /js\/vendor\/mermaid\.min\.js/);
});


test("all indexable pages omit status panels and page TOCs while retaining navigation", () => {
  for (const url of indexableUrls) {
    const html = readPage(url);
    assert.doesNotMatch(html, /class="(?:docs-evidence|docs-mobile-toc|docs-lab-status|docs-card__status)|md-sidebar--secondary/, url);
    assert.match(html, /id="docs-navigation"/, url);
    assert.match(html, /class="docs-nav-section"/, url);
    assert.doesNotMatch(html, /<details class="docs-nav-section" open/, url);
  }
});
