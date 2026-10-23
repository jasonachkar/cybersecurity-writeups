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

test("article metadata, actions, relationships, sidebar and footer match catalog", async () => {
  const item = catalog.research.find(candidate => candidate.id === "ai-agent-security");
  const {context, page, errors} = await pageAt(item.url);
  assert.equal(await page.locator("h1").textContent(), item.title);
  assert.equal(await page.locator(".docs-article-header__summary").textContent(), item.summary);
  assert.equal(await page.locator(".docs-evidence").count(), 0);
  assert.equal(await page.locator(`.docs-article-actions a[href='${item.github.view}']`).count(), 1);
  assert.equal(await page.locator("a[href*='/edit/main/']").count(), 0);
  assert.equal(await page.locator(".docs-related__item").count(), Object.values(item.related).flat().length);
  assert.ok(await page.locator(".docs-sidebar").isVisible());
  assert.ok(await page.locator(".docs-pagination a").count() > 0);
  assert.equal(await page.locator(".docs-sidebar a[aria-current=page]").textContent(), item.navTitle);
  assert.equal(await page.locator(".docs-toc, .docs-mobile-toc").count(), 0);
  assert.equal(errors.length, 0, errors.join("\n"));
  await context.close();
});

test("desktop Focus mode persists, hides both rails, and restores focus on exit", async () => {
  const {context, page, errors} = await pageAt("/appsec/ai-agent-security/");
  const button = page.locator("[data-docs-focus]");
  await button.click();
  assert.equal(await button.getAttribute("aria-pressed"), "true");
  assert.equal(await page.locator("body").evaluate(element => element.classList.contains("docs-focus-mode")), true);
  assert.equal(await page.locator(".docs-sidebar").evaluate(element => getComputedStyle(element).display), "none");
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
  const primaryAction = page.locator(".docs-hero__actions a").first();
  const primaryLabel = primaryAction.locator(".docs-link-label");
  assert.equal(await primaryAction.locator(".docs-link-arrow").isVisible(), true);
  assert.equal(await primaryAction.evaluate(link => getComputedStyle(link).textDecorationLine), "none");
  const restingBorder = await primaryLabel.evaluate(label => getComputedStyle(label).borderBottomColor);
  await primaryAction.hover();
  assert.equal(await primaryAction.evaluate(link => getComputedStyle(link).textDecorationLine), "none");
  assert.notEqual(await primaryLabel.evaluate(label => getComputedStyle(label).borderBottomColor), restingBorder);
  assert.equal(await primaryLabel.evaluate(label => {
    const styles = getComputedStyle(label);
    return styles.borderBottomColor === styles.color;
  }), true);
  const featuredCard = page.locator(".docs-card-grid--featured > .docs-card").first();
  const featuredTitle = featuredCard.locator("h3 .docs-link-label");
  await featuredCard.hover();
  assert.equal(await featuredTitle.evaluate(label => {
    const styles = getComputedStyle(label);
    return styles.borderBottomColor === styles.color;
  }), true);
  assert.equal(await featuredCard.locator("p").evaluate(description => getComputedStyle(description).textDecorationLine), "none");
  const recentTitles = (await page.locator(".docs-recent strong").allTextContents()).map(title => title.replace(/\s+→$/, ""));
  assert.deepEqual(recentTitles, catalog.recent.map(item => item.navTitle));
  await page.locator("[data-docs-search-open]").first().click();
  assert.equal(await page.locator("#__search").isChecked(), true);
  await page.keyboard.press("Escape");
  assert.equal(await page.locator(".docs-sidebar a[href='appsec/'], .docs-sidebar a[href='/appsec/']").count() > 0, true);
  assert.equal(errors.length, 0, errors.join("\n"));
  await context.close();
});

test("source viewer switches files, wraps, expands, and updates canonical links", async () => {
  const {context, page, errors} = await pageAt("/labs/ai-agent-security/");
  const viewer = page.locator("[data-source-viewer]");
  assert.equal(await viewer.locator("[role=tab]").count(), 2);
  const sourceLink = viewer.locator("a[data-source-github]");
  const sourceLabel = sourceLink.locator(".docs-link-label");
  assert.equal(await sourceLink.locator(".docs-link-arrow").isVisible(), true);
  assert.equal(await sourceLink.evaluate(link => getComputedStyle(link).textDecorationLine), "none");
  const restingBorder = await sourceLabel.evaluate(label => getComputedStyle(label).borderBottomColor);
  await sourceLink.hover();
  assert.equal(await sourceLink.evaluate(link => getComputedStyle(link).textDecorationLine), "none");
  assert.notEqual(await sourceLabel.evaluate(label => getComputedStyle(label).borderBottomColor), restingBorder);
  assert.equal(await sourceLabel.evaluate(label => {
    const styles = getComputedStyle(label);
    return styles.borderBottomColor === styles.color;
  }), true);
  const lightTokenColors = await viewer.locator(".docs-source-viewer__line-content span[style*='--shiki-light']").evaluateAll(tokens => [...new Set(tokens.map(token => getComputedStyle(token).color))]);
  assert.ok(lightTokenColors.length >= 3, `expected a light syntax palette, received ${lightTokenColors.join(", ")}`);
  await page.locator("body").evaluate(body => body.setAttribute("data-md-color-scheme", "slate"));
  const darkTokenColors = await viewer.locator(".docs-source-viewer__line-content span[style*='--shiki-dark']").evaluateAll(tokens => [...new Set(tokens.map(token => getComputedStyle(token).color))]);
  assert.ok(darkTokenColors.length >= 3, `expected a dark syntax palette, received ${darkTokenColors.join(", ")}`);
  assert.notDeepEqual(lightTokenColors, darkTokenColors);
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

test("article Mermaid diagrams render locally and follow the selected theme", async () => {
  const {context, page, errors} = await pageAt("/devsecops/secure-cicd-pipeline-design/");
  const diagram = page.locator("div.mermaid");
  await diagram.waitFor({state: "visible"});
  const diagramBox = await diagram.boundingBox();
  assert.ok(diagramBox.height > 100, `expected a rendered diagram, received ${diagramBox.height}px`);
  assert.equal(await page.locator("pre.mermaid").count(), 0);
  assert.equal(await page.evaluate(() => typeof window.mermaid), "object");
  assert.equal(await page.evaluate(() => performance.getEntriesByType("resource").some(entry => entry.name.includes("unpkg.com/mermaid"))), false);
  const lightLabelColor = await diagram.evaluate(element => getComputedStyle(element).getPropertyValue("--md-mermaid-label-fg-color"));
  await page.locator("[data-docs-theme]").first().selectOption("dark");
  await page.waitForFunction(previous => {
    const current = document.querySelector("div.mermaid");
    return document.body.dataset.mdColorScheme === "slate" && current
      && getComputedStyle(current).getPropertyValue("--md-mermaid-label-fg-color") !== previous;
  }, lightLabelColor);
  assert.equal(await diagram.isVisible(), true);
  assert.equal(errors.length, 0, errors.join("\n"));
  await context.close();
});

test("theme switching and representative layouts have no horizontal page overflow", async () => {
  for (const viewport of [{width: 390, height: 844}, {width: 1024, height: 768}, {width: 1440, height: 900}]) {
    const {context, page, errors} = await pageAt("/appsec/ai-agent-security/", viewport);
    const palette = page.locator(viewport.width < 800 ? ".docs-sidebar [data-docs-theme]" : ".docs-header [data-docs-theme]");
    if (viewport.width < 800) await page.locator("[data-docs-menu]").click();
    await palette.selectOption("dark");
    if (viewport.width < 800) await page.keyboard.press("Escape");
    assert.equal(await page.locator("body").getAttribute("data-md-color-scheme"), "slate");
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    assert.ok(overflow <= 1, `${viewport.width}: horizontal overflow ${overflow}px`);
    if (viewport.width < 1220) assert.equal(await page.locator("[data-docs-focus]").isVisible(), false);
    assert.equal(errors.length, 0, errors.join("\n"));
    await context.close();
  }
});

test("new research is readable on narrow screens with rendered diagrams", async () => {
  for (const width of [320, 390, 768]) {
    for (const url of ["/ai-security/evidence-driven-agent-security/", "/linux-security/evidence-driven-host-analysis/", "/devsecops/evidence-preserving-security-pipelines/"]) {
      const {context, page, errors} = await pageAt(url, {width, height: 844});
      await page.waitForFunction(() => document.querySelectorAll("div.mermaid").length === 3 && document.querySelectorAll("pre.mermaid").length === 0);
      for (const diagram of await page.locator("div.mermaid").all()) {
        assert.ok((await diagram.boundingBox()).height > 40);
      }
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), `${url} overflows at ${width}px`);
      assert.equal(errors.length, 0, errors.join("\n"));
      await context.close();
    }
  }
});

test("mobile navigation fills the area below the header, collapses groups, and restores focus", async () => {
  const {context, page, errors} = await pageAt("/appsec/ai-agent-security/", {width: 390, height: 844});
  const menu = page.locator("[data-docs-menu]");
  await menu.click();
  assert.equal(await menu.getAttribute("aria-expanded"), "true");
  const box = await page.locator(".docs-sidebar").boundingBox();
  assert.equal(box.x, 0);
  assert.equal(box.y, 64);
  assert.equal(box.width, 390);
  assert.equal(box.height, 780);
  assert.equal(await page.locator(".md-content").evaluate(node => node.inert), true);
  const group = page.locator(".docs-sidebar__start");
  await group.locator("summary").click();
  assert.equal(await group.getAttribute("open"), null);
  await group.locator("summary").click();
  assert.equal(await group.evaluate(node => node.open), true);
  await page.keyboard.press("Escape");
  assert.equal(await menu.getAttribute("aria-expanded"), "false");
  assert.equal(await menu.evaluate(node => node === document.activeElement), true);
  assert.equal(await page.locator(".md-content").evaluate(node => node.inert), false);
  assert.equal(errors.length, 0, errors.join("\n"));
  await context.close();
});

test("header search returns real results, is centered, and supports its keyboard shortcut", async () => {
  const {context, page, errors} = await pageAt("/appsec/ai-agent-security/");
  await page.keyboard.press("Control+k");
  await page.locator(".md-search__input").fill("tenant isolation");
  await page.waitForFunction(() => document.querySelectorAll(".md-search-result__item").length > 0);
  const box = await page.locator(".md-search__inner").boundingBox();
  assert.ok(Math.abs(box.x + box.width / 2 - 720) < 2);
  await page.keyboard.press("Escape");
  assert.equal(await page.locator("#__search").isChecked(), false);
  assert.equal(errors.length, 0, errors.join("\n"));
  await context.close();
});

test("theme selector remembers dark mode and auto follows the device preference", async () => {
  const {context, page, errors} = await pageAt("/appsec/ai-agent-security/");
  const theme = page.locator(".docs-header [data-docs-theme]");
  await theme.selectOption("dark");
  await page.reload();
  assert.equal(await theme.inputValue(), "dark");
  assert.equal(await page.locator("body").getAttribute("data-md-color-scheme"), "slate");
  await theme.selectOption("auto");
  await page.emulateMedia({colorScheme: "light"});
  await page.waitForFunction(() => document.body.dataset.mdColorScheme === "default");
  await page.emulateMedia({colorScheme: "dark"});
  await page.waitForFunction(() => document.body.dataset.mdColorScheme === "slate");
  assert.equal(errors.length, 0, errors.join("\n"));
  await context.close();
});
