import assert from "node:assert/strict";
import test, {after, before} from "node:test";
import {chromium} from "playwright";
import {createRequire} from "node:module";
import {serveSite} from "./site-helper.mjs";

const require = createRequire(import.meta.url);
const catalog = require("../../scripts/docs-catalog-lib.js").buildCatalog();
let browser;
let server;
before(async () => { server = await serveSite(); browser = await chromium.launch(); });
after(async () => { await browser?.close(); await server?.close(); });

async function pageAt(url, viewport = {width: 1440, height: 900}) {
  const context = await browser.newContext({viewport, colorScheme: "light"});
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", error => errors.push(String(error)));
  page.on("console", message => { if (message.type() === "error") errors.push(message.text()); });
  const response = await page.goto(`${server.base}${url}`, {waitUntil: "load"});
  assert.equal(response.status(), 200);
  return {context, page, errors};
}

test("article metadata, actions, relationships, breadcrumbs, and TOC match catalog", async () => {
  const item = catalog.research.find(candidate => candidate.id === "ai-agent-security");
  const {context, page, errors} = await pageAt(item.url);
  assert.equal(await page.locator("h1").textContent(), item.title);
  assert.equal(await page.locator(".docs-article-header__summary").textContent(), item.summary);
  assert.equal(await page.locator(".docs-evidence__grid dd").nth(0).textContent(), item.implementationLabel);
  assert.equal(await page.locator(`.docs-article-actions a[href='${item.github.view}']`).count(), 1);
  assert.equal(await page.locator(".docs-related__item").count(), 1);
  assert.ok(await page.locator(".md-path").isVisible());
  assert.ok(await page.locator(".md-sidebar--secondary").isVisible());
  assert.equal(errors.length, 0, errors.join("\n"));
  await context.close();
});

test("desktop Focus mode persists, hides both rails, and restores focus on exit", async () => {
  const {context, page, errors} = await pageAt("/appsec/ai-agent-security/");
  const button = page.locator("[data-docs-focus]");
  await button.click();
  assert.equal(await button.getAttribute("aria-pressed"), "true");
  assert.equal(await page.locator("body").evaluate(element => element.classList.contains("docs-focus-mode")), true);
  assert.equal(await page.locator(".md-sidebar--primary").evaluate(element => getComputedStyle(element).display), "none");
  assert.equal(await page.locator(".md-sidebar--secondary").evaluate(element => getComputedStyle(element).display), "none");
  await page.reload({waitUntil: "load"});
  assert.equal(await page.locator("body").evaluate(element => element.classList.contains("docs-focus-mode")), true);
  await page.locator("[data-docs-focus]").click();
  assert.equal(await page.locator("[data-docs-focus]").evaluate(element => element === document.activeElement), true);
  assert.equal(errors.length, 0, errors.join("\n"));
  await context.close();
});

test("homepage ordering, search trigger, and navigation are data-driven", async () => {
  const {context, page, errors} = await pageAt("/");
  assert.equal(await page.locator(".docs-card-grid--featured > .docs-card").count(), 4);
  assert.deepEqual(await page.locator(".docs-recent strong").allTextContents(), catalog.recent.map(item => item.navTitle));
  await page.locator("[data-docs-search-open]").click();
  assert.equal(await page.locator("#__search").isChecked(), true);
  await page.keyboard.press("Escape");
  assert.equal(await page.locator(".md-nav--primary a[href='appsec/'], .md-nav--primary a[href='/appsec/']").count() > 0, true);
  assert.equal(errors.length, 0, errors.join("\n"));
  await context.close();
});

test("source viewer switches files, wraps, expands, and updates canonical links", async () => {
  const {context, page, errors} = await pageAt("/labs/ai-agent-security/");
  const viewer = page.locator("[data-source-viewer]");
  assert.equal(await viewer.locator("[role=tab]").count(), 2);
  const second = viewer.locator("[role=tab]").nth(1);
  await second.focus();
  await page.keyboard.press("Enter");
  assert.equal(await second.getAttribute("aria-selected"), "true");
  assert.match(await viewer.locator("[data-source-active-path]").textContent(), /tests\/broker\.test\.js$/);
  assert.match(await viewer.locator("a[data-source-github]").getAttribute("href"), /blob\/main\/labs\/ai-agent-security\/tests\/broker\.test\.js$/);
  await viewer.locator("[data-wrap-source]").click();
  assert.equal(await viewer.locator("[data-wrap-source]").getAttribute("aria-pressed"), "true");
  const expand = viewer.locator("[data-expand-source]");
  if (await expand.isVisible()) {
    await expand.click();
    assert.equal(await expand.getAttribute("aria-expanded"), "true");
  }
  assert.equal(errors.length, 0, errors.join("\n"));
  await context.close();
});

test("theme switching and representative layouts have no horizontal page overflow", async () => {
  for (const viewport of [{width: 390, height: 844}, {width: 1024, height: 768}, {width: 1440, height: 900}]) {
    const {context, page, errors} = await pageAt("/appsec/ai-agent-security/", viewport);
    const palette = page.locator("label.md-header__button[for^='__palette']").first();
    await palette.click();
    assert.equal(await page.locator("body").getAttribute("data-md-color-scheme"), "slate");
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    assert.ok(overflow <= 1, `${viewport.width}: horizontal overflow ${overflow}px`);
    if (viewport.width < 1220) assert.equal(await page.locator("[data-docs-focus]").isVisible(), false);
    assert.equal(errors.length, 0, errors.join("\n"));
    await context.close();
  }
});
