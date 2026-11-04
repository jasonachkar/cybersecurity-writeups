import fs from "node:fs";
import path from "node:path";
import {createRequire} from "node:module";
import assert from "node:assert/strict";
import test, {before, after} from "node:test";
import {chromium, webkit, devices} from "playwright";
import {expect} from "playwright/test";
import {serveSite, indexableUrls, writeReport, ARTIFACTS} from "./site-helper.mjs";

let server;
const engines = [{name: "Chromium", type: chromium, device: "Pixel 7"}, {name: "WebKit", type: webkit, device: "iPhone 13"}];
const results = [];
const errors = [];
const axeSource = fs.readFileSync(createRequire(import.meta.url).resolve("axe-core/axe.min.js"), "utf8");
before(async () => { server = await serveSite(); for (const engine of engines) engine.browser = await engine.type.launch(); });
after(async () => { for (const engine of engines) await engine.browser?.close(); await server?.close(); writeReport(`mobile-report-${process.platform}.json`, {results, errors, physicalDevice: false, limitations: process.platform === "linux" ? ["The pinned Linux headless container does not scroll the plain-page control under CDP touch-gesture injection; native gestures are checked on macOS."] : []}); assert.deepEqual(errors, []); });

async function mobile(engine, width = 390, height = 844, colorScheme = "light") {
  const {defaultBrowserType, ...device} = devices[engine.device];
  const context = await engine.browser.newContext({...device, viewport: {width, height}, colorScheme});
  const page = await context.newPage();
  page.setDefaultTimeout(8000);
  page.on("pageerror", error => errors.push(`${engine.name}: ${error.message}`));
  return {context, page};
}
async function capture(page, engine, state) {
  const directory = path.join(ARTIFACTS, "mobile", process.platform);
  fs.mkdirSync(directory, {recursive: true});
  await page.screenshot({path: path.join(directory, `${engine.name.toLowerCase()}-${state}.png`), scale: "css", animations: "disabled"});
}
async function visit(page, url) {
  const response = await page.goto(`${server.base}${url}`, {waitUntil: "load"});
  assert.equal(response.status(), 200, url);
}
async function closedDrawer(page) {
  await expect.poll(async () => page.locator(".md-sidebar--primary").evaluate(element => element.getBoundingClientRect().right)).toBeLessThanOrEqual(1);
  assert.equal(await page.locator(".md-sidebar--primary").evaluate(element => element.inert), true);
}
async function layout(page, label) {
  await closedDrawer(page);
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), `${label}: page overflow`);
  const heading = page.locator("h1").first();
  assert.ok(await heading.isVisible(), `${label}: heading missing`);
  const hit = await heading.evaluate(element => {
    const box = element.getBoundingClientRect();
    return box.left >= 10 && box.right <= innerWidth - 10 && element.contains(document.elementFromPoint(box.left + 3, box.top + 3));
  });
  assert.equal(hit, true, `${label}: heading is clipped or covered`);
  for (const selector of [".docs-brand", ".docs-mobile-search", ".docs-menu"]) {
    const target = page.locator(selector);
    if (await target.isVisible()) {
      const box = await target.boundingBox();
      assert.ok(box.x >= 0 && box.x + box.width <= await page.evaluate(() => innerWidth) + 1, `${label}: ${selector} off-screen`);
      assert.ok(box.width >= 44 && box.height >= 44, `${label}: ${selector} touch target too small`);
    }
  }
}

for (const engine of engines) {
  test(`${engine.name}: all indexable pages fit a small phone without a drawer overlay`, async () => {
    const {context, page} = await mobile(engine, 320, 740);
    for (const url of indexableUrls) { await visit(page, url); await layout(page, `${engine.name} 320 ${url}`); if (url === "/") await capture(page, engine, "home-320"); }
    results.push({engine: engine.name, audit: "all routes", routes: indexableUrls.length, width: 320});
    await context.close();
  });

  test(`${engine.name}: phone, landscape, and tablet layouts work in both themes`, async () => {
    for (const [width, height] of [[360, 800], [390, 844], [430, 932], [768, 1024], [844, 390], [1024, 768]]) {
      for (const scheme of ["light", "dark"]) {
        const {context, page} = await mobile(engine, width, height, scheme);
        for (const url of ["/", "/appsec/ai-agent-security/", "/scripts/devsecops/", "/labs/ai-agent-security/"]) {
          await visit(page, url); await layout(page, `${engine.name} ${width} ${scheme} ${url}`);
        }
        await context.close();
      }
    }
    results.push({engine: engine.name, audit: "responsive matrix", widths: [360, 390, 430, 768, 844, 1024], themes: 2, pageTypes: 4});
  });

  test(`${engine.name}: touch menu, focus containment, dismissal, and rotation`, async () => {
    const {context, page} = await mobile(engine);
    await visit(page, "/appsec/ai-agent-security/");
    await page.locator(".docs-menu").tap();
    await expect(page.locator(".md-sidebar--primary")).toHaveAttribute("aria-modal", "true");
    await expect(page.locator(".docs-nav-close")).toBeFocused();
    assert.equal(await page.locator(".md-content").evaluate(element => element.inert), true);
    await capture(page, engine, "drawer");
    await page.keyboard.press("Shift+Tab");
    assert.equal(await page.evaluate(() => document.getElementById("docs-navigation").contains(document.activeElement)), true);
    await page.keyboard.press("Tab");
    await expect(page.locator(".docs-nav-close")).toBeFocused();
    await page.locator(".docs-nav-close").tap();
    await closedDrawer(page);
    await expect(page.locator(".docs-menu")).toBeFocused();
    await page.locator(".docs-menu").tap();
    await page.locator(".md-overlay").tap({position: {x: 380, y: 300}});
    await closedDrawer(page);
    await page.locator(".docs-menu").tap();
    await page.keyboard.press("Escape");
    await closedDrawer(page);
    await page.locator(".docs-menu").tap();
    await page.setViewportSize({width: 1440, height: 900});
    assert.equal(await page.locator(".md-sidebar--primary").evaluate(element => element.inert), false);
    await expect(page.locator("#__drawer")).not.toBeChecked();
    await context.close();
  });

  test(`${engine.name}: mobile search focuses, finds results, and navigates`, async () => {
    const {context, page} = await mobile(engine, 320, 740);
    await visit(page, "/");
    await page.locator(".docs-mobile-search").tap();
    const query = page.locator(".md-search__input");
    await expect(query).toBeFocused();
    assert.equal(await page.locator(".md-content").evaluate(element => element.inert), true);
    await page.keyboard.press("Shift+Tab");
    assert.equal(await page.evaluate(() => document.querySelector(".md-search").contains(document.activeElement)), true);
    await query.focus();
    assert.ok(await query.evaluate(element => parseFloat(getComputedStyle(element).fontSize)) >= 16);
    await page.locator(".docs-search-back").tap();
    await expect(page.locator("#__search")).not.toBeChecked();
    await expect(page.locator(".docs-mobile-search")).toBeFocused();
    await page.locator(".docs-mobile-search").tap();
    await page.setViewportSize({width: 320, height: 420});
    await query.fill("AI agent");
    const result = page.locator(".md-search-result__link").first();
    await expect(result).toBeVisible();
    const preview = result.locator(".md-search-result__article > p").first();
    assert.ok(await preview.evaluate(element => element.getBoundingClientRect().height <= parseFloat(getComputedStyle(element).lineHeight) * 4 + 1));
    assert.equal(await page.locator(".md-search__suggest").isVisible(), false);
    await capture(page, engine, "search");
    const destination = new URL(await result.getAttribute("href"), page.url());
    await result.tap();
    await page.waitForURL(url => url.pathname === destination.pathname);
    await expect(page.locator("#__search")).not.toBeChecked();
    await layout(page, `${engine.name} search result`);
    await context.close();
  });

  test(`${engine.name}: source controls and pagination work by touch`, async () => {
    const {context, page} = await mobile(engine, 320, 740);
    await visit(page, "/labs/ai-agent-security/");
    const viewer = page.locator("[data-source-viewer]");
    await viewer.locator("[data-wrap-source]").tap();
    await expect(viewer.locator("[data-wrap-source]")).toHaveAttribute("aria-pressed", "true");
    assert.ok(await viewer.locator(".docs-source-viewer__panel:not([hidden])").evaluate(element => element.scrollWidth <= element.clientWidth + 1));
    const firstExpand = viewer.locator("[data-expand-source]");
    if (await firstExpand.isVisible()) await firstExpand.tap();
    await viewer.locator("[role=tab]").nth(1).tap();
    if (await firstExpand.isVisible()) await expect(firstExpand).toHaveText("Expand");
    await expect(viewer.locator("[role=tab]").nth(1)).toHaveAttribute("aria-selected", "true");
    await viewer.locator("[data-copy-source]").tap();
    await expect(viewer.locator("[data-source-status]")).toHaveText(/Source copied|Copy unavailable; use View raw/);
    const expand = viewer.locator("[data-expand-source]");
    if (await expand.isVisible()) { await expand.tap(); await expect(expand).toHaveAttribute("aria-expanded", "true"); await expand.tap(); }
    const next = page.locator(".md-footer__link--next");
    const expected = new URL(await next.getAttribute("href"), page.url()).pathname;
    await next.scrollIntoViewIfNeeded();
    await expect(page.locator(".md-footer__link--prev .md-footer__title")).toBeVisible();
    await capture(page, engine, "pagination");
    await next.tap();
    await page.waitForURL(url => url.pathname === expected);
    assert.equal(new URL(page.url()).pathname, expected);
    await closedDrawer(page);
    await context.close();
  });

  test(`${engine.name}: open navigation and search pass accessibility checks`, async () => {
    for (const scheme of ["light", "dark"]) {
      const {context, page} = await mobile(engine, 390, 844, scheme);
      await visit(page, "/appsec/ai-agent-security/");
      await page.addScriptTag({content: axeSource});
      for (const selector of [".docs-menu", ".docs-mobile-search"]) {
        await page.locator(selector).tap();
        const violations = await page.evaluate(async () => (await window.axe.run(document, {runOnly: {type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"]}})).violations.map(item => ({id: item.id, targets: item.nodes.map(node => node.target)})));
        assert.deepEqual(violations, [], `${engine.name} ${scheme} ${selector}`);
        await page.keyboard.press("Escape");
      }
      await context.close();
    }
  });

  test(`${engine.name}: diagram controls are reachable and reset the mobile view`, async () => {
    const {context, page} = await mobile(engine, 320, 740);
    await visit(page, "/devsecops/secure-cicd-pipeline-design/");
    const diagram = page.locator(".docs-mermaid").first();
    await expect(diagram).toBeVisible();
    for (const button of await diagram.locator("button").all()) {
      const box = await button.boundingBox();
      assert.ok(box.width >= 44 && box.height >= 44, `${engine.name}: diagram touch target`);
    }
    await diagram.scrollIntoViewIfNeeded();
    await capture(page, engine, "diagram");
    await diagram.locator("[data-mermaid-zoom-in]").tap();
    await expect(diagram.locator("[data-mermaid-zoom-level]")).toHaveText("150%");
    const zoomIn = diagram.locator("[data-mermaid-zoom-in]");
    for (let step = 0; step < 10 && await zoomIn.isEnabled(); step++) await zoomIn.tap();
    await expect(diagram.locator("[data-mermaid-zoom-level]")).toHaveText("800%");
    await expect(zoomIn).toBeDisabled();
    await diagram.locator("[data-mermaid-reset]").tap();
    await expect(diagram.locator("[data-mermaid-zoom-level]")).toHaveText("100%");
    assert.match(await diagram.locator(".mermaid").evaluate(element => getComputedStyle(element).touchAction), /pan-y/);
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
    await context.close();
  });
}


test("Chromium: touch scrolling remains native until a diagram is zoomed", {skip: process.platform !== "darwin" && "Native gesture injection is validated on macOS; the Linux headless control does not scroll."}, async () => {
  const engine = engines[0];
  const {context, page} = await mobile(engine);
  await visit(page, "/devsecops/secure-cicd-pipeline-design/");
  const diagram = page.locator(".docs-mermaid").first();
  await expect(diagram).toBeVisible();
  const session = await context.newCDPSession(page);
  const viewport = diagram.locator(".docs-mermaid__viewport");
  async function swipe(deltaX, deltaY, target = viewport) {
    // Let style changes reach the compositor before starting a native gesture.
    const frame = () => page.evaluate(() => new Promise(requestAnimationFrame));
    await frame(); await frame();
    const box = await target.boundingBox();
    const x = box.x + box.width / 2;
    const y = box.y + box.height / 2;
    await session.send("Input.dispatchTouchEvent", {type: "touchStart", touchPoints: [{x, y, id: 1}]});
    for (let step = 1; step <= 6; step++) {
      await frame();
      await session.send("Input.dispatchTouchEvent", {type: "touchMove", touchPoints: [{x: x + deltaX * step / 6, y: y + deltaY * step / 6, id: 1}]});
    }
    await session.send("Input.dispatchTouchEvent", {type: "touchEnd", touchPoints: []});
  }
  await diagram.locator("[data-mermaid-zoom-in]").tap();
  await viewport.scrollIntoViewIfNeeded();
  const before = await page.evaluate(() => scrollY);
  await swipe(50, -30);
  assert.match(await diagram.locator(".mermaid").getAttribute("style"), /translate/);
  assert.equal(await page.evaluate(() => scrollY), before, "enlarged diagram pans without scrolling the page");
  await diagram.locator("[data-mermaid-reset]").tap();
  await viewport.scrollIntoViewIfNeeded();
  const reset = await page.evaluate(() => scrollY);
  const diagramBox = await viewport.boundingBox();
  await session.send("Input.synthesizeScrollGesture", {x: diagramBox.x + diagramBox.width / 2, y: diagramBox.y + diagramBox.height / 2, yDistance: -150, speed: 400, gestureSourceType: "touch"});
  await expect.poll(() => page.evaluate(() => scrollY)).toBeGreaterThan(reset + 30);
  await visit(page, "/labs/ai-agent-security/");
  const panel = page.locator(".docs-source-viewer__panel:not([hidden])");
  await panel.scrollIntoViewIfNeeded();
  await panel.evaluate(element => { element.scrollTop = 0; });
  const panelBox = await panel.boundingBox();
  await session.send("Input.synthesizeScrollGesture", {x: panelBox.x + panelBox.width / 2, y: panelBox.y + panelBox.height / 2, yDistance: -150, speed: 400, gestureSourceType: "touch"});
  await expect.poll(() => panel.evaluate(element => element.scrollTop)).toBeGreaterThan(30);
  await context.close();
});
