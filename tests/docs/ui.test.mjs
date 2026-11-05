import assert from "node:assert/strict";
import test, {after, before} from "node:test";
import {chromium} from "playwright";
import {createRequire} from "node:module";
import {serveSite} from "./site-helper.mjs";
import {rawMarkdownInArticle, scriptCategories, scriptLinks, studyNoteRoutes, studyGuideUrl} from "./markdown-content.mjs";

const require = createRequire(import.meta.url);
const catalog = require("../../scripts/docs-catalog-lib.js").buildCatalog();
let browser;
let server;
before(async () => { server = await serveSite(); browser = await chromium.launch(); });
after(async () => { await browser?.close(); await server?.close(); });

async function pageAt(url, viewport = {width: 1440, height: 900}, colorScheme = "light") {
  const context = await browser.newContext({viewport, colorScheme});
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", error => errors.push(String(error)));
  page.on("console", message => { if (message.type() === "error") errors.push(message.text()); });
  const response = await page.goto(`${server.base}${url}`, {waitUntil: "load"});
  assert.equal(response.status(), 200);
  return {context, page, errors};
}

test("repaired Markdown renders and navigates on desktop/mobile in both themes", async () => {
  for (const viewport of [{width: 1440, height: 900}, {width: 390, height: 844}]) {
    for (const scheme of ["light", "dark"]) {
      for (const url of ["/scripts/", ...studyNoteRoutes]) {
        const {context, page, errors} = await pageAt(url, viewport, scheme);
        try {
          const article = page.locator("article.md-content__inner");
          assert.equal(await page.locator("body").getAttribute("data-md-color-scheme"), scheme === "dark" ? "slate" : "default");
          assert.equal(await article.locator("h1").count(), 1);
          assert.deepEqual(await article.evaluate(rawMarkdownInArticle), [], url);
          if (url === "/scripts/") {
            for (const {title, id, url: categoryUrl} of scriptCategories) {
              const heading = article.getByRole("heading", {level: 2, name: new RegExp(`^${title}\\s*¶?$`)});
              assert.equal(await heading.count(), 1);
              assert.equal(await heading.getAttribute("id"), id);
              const link = article.getByRole("link", {name: `Open the ${title} category`, exact: true});
              await link.click();
              assert.equal(new URL(page.url()).pathname, categoryUrl);
              assert.equal(await page.locator("article .docs-source-viewer").count() > 0, true);
              await page.goto(`${server.base}${url}`, {waitUntil: "load"});
            }
            for (const [title, href] of scriptLinks) {
              const link = article.getByRole("link", {name: title, exact: true});
              assert.equal(await link.getAttribute("href"), href);
              await link.click();
              const destination = new URL(page.url());
              assert.equal(`${destination.pathname}${destination.hash}`, href);
              const target = page.locator(destination.hash);
              assert.equal(await target.count(), 1, href);
              assert.equal(await target.locator("h2").count(), 1);
              await page.goto(`${server.base}${url}`, {waitUntil: "load"});
            }
            const list = article.locator("ul:has(> li > a[href$='#kyverno-policy-schema-check'])");
            const items = list.locator(":scope > li");
            assert.equal(await items.count(), 2);
            const first = await items.nth(0).boundingBox();
            const second = await items.nth(1).boundingBox();
            assert.ok(second.y >= first.y + first.height, "validator items must occupy separate lines");
            const headings = await article.locator("h2").all();
            for (const heading of headings) {
              const headingBox = await heading.boundingBox();
              const nextBox = await heading.locator("xpath=following-sibling::p[1]").boundingBox();
              assert.ok(nextBox.y > headingBox.y + headingBox.height, "heading/link spacing");
            }
          } else {
            const aside = article.locator("aside.study-currency");
            assert.equal(await aside.getByRole("link", {name: "Official SC-500 study guide", exact: true}).getAttribute("href"), studyGuideUrl);
            assert.equal(await aside.locator("strong").count(), 2);
            assert.equal(await aside.isVisible(), true);
          }
          assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), `${url} ${viewport.width}/${scheme}: overflow`);
          assert.ok(await page.locator("#docs-navigation").count() === 1);
          assert.equal(errors.length, 0, errors.join("\n"));
        } finally { await context.close(); }
      }
    }
  }
});

test("article metadata, actions, relationships, and breadcrumbs match catalog without status panels", async () => {
  const item = catalog.research.find(candidate => candidate.id === "ai-agent-security");
  const {context, page, errors} = await pageAt(item.url);
  assert.equal(await page.locator("h1").textContent(), item.title);
  assert.equal(await page.locator(".docs-article-header__summary").textContent(), item.summary);
  assert.equal(await page.locator(".docs-evidence, .docs-mobile-toc, .docs-lab-status").count(), 0);
  assert.equal(await page.locator(`.docs-article-actions a[href='${item.github.view}']`).count(), 1);
  assert.equal(await page.locator("a[href*='/edit/main/']").count(), 0);
  assert.equal(await page.locator(".docs-related__item").count(), Object.values(item.related).flat().length);
  assert.ok(await page.locator(".md-path").isVisible());
  assert.equal(await page.locator(".md-sidebar--secondary").count(), 0);
  assert.equal(errors.length, 0, errors.join("\n"));
  await context.close();
});

test("desktop Focus mode persists, hides navigation, and restores focus on exit", async () => {
  const {context, page, errors} = await pageAt("/appsec/ai-agent-security/");
  const button = page.locator("[data-docs-focus]");
  await button.click();
  assert.equal(await button.getAttribute("aria-pressed"), "true");
  assert.equal(await page.locator("body").evaluate(element => element.classList.contains("docs-focus-mode")), true);
  assert.equal(await page.locator(".md-sidebar--primary").evaluate(element => getComputedStyle(element).display), "none");
  assert.equal(await page.locator(".md-sidebar--secondary").count(), 0);
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
  await page.locator(".docs-hero-search").click();
  assert.equal(await page.locator("#__search").isChecked(), true);
  await page.locator(".docs-search-back").click();
  assert.equal(await page.locator("#__search").isChecked(), false);
  assert.equal(await page.locator(".md-nav--primary a[href='appsec/'], .md-nav--primary a[href='/appsec/']").count() > 0, true);
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
  assert.ok(lightTokenColors.some(color => {
    const rgb = color.match(/\d+/g).map(Number);
    return rgb[0] !== rgb[1] || rgb[1] !== rgb[2];
  }), "source syntax highlighting must retain chromatic colors");
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
  assert.equal(await diagram.evaluate(element => getComputedStyle(element).filter), "none");
  const nodeColor = await diagram.evaluate(element => getComputedStyle(element).getPropertyValue("--md-mermaid-node-bg-color").trim());
  assert.equal(nodeColor, "#e0e7ff", "diagram node palette stays colorful independently of interface accents");
  const lightLabelColor = await diagram.evaluate(element => getComputedStyle(element).getPropertyValue("--md-mermaid-label-fg-color"));
  await page.locator("label.md-header__button[for^='__palette']").first().click();
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

test("new research is readable on narrow screens with navigable sections and rendered diagrams", async () => {
  for (const width of [320, 390, 768]) {
    for (const url of ["/ai-security/evidence-driven-agent-security/", "/linux-security/evidence-driven-host-analysis/", "/devsecops/evidence-preserving-security-pipelines/"]) {
      const {context, page, errors} = await pageAt(url, {width, height: 844});
      await page.waitForFunction(() => document.querySelectorAll("div.mermaid").length === 3 && document.querySelectorAll("pre.mermaid").length === 0);
      for (const diagram of await page.locator("div.mermaid").all()) {
        assert.ok((await diagram.boundingBox()).height > 40);
      }
      assert.equal(await page.locator(".docs-mobile-toc").count(), 0);
      const section = page.locator("h2 .headerlink").first();
      const target = await section.getAttribute("href");
      await section.click();
      assert.equal(new URL(page.url()).hash, target);
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), `${url} overflows at ${width}px`);
      assert.equal(errors.length, 0, errors.join("\n"));
      await context.close();
    }
  }
});

test("vulnerability studies expose their evidence limits, diagrams and runnable labs", async () => {
  for (const width of [390, 1440]) {
    for (const slug of ["mcp-tool-ssrf", "api-bola-multi-tenant", "cicd-identity-escalation"]) {
      const item = catalog.research.find(candidate => candidate.id === slug);
      const {context, page, errors} = await pageAt(item.url, {width, height: 900});
      await page.waitForFunction(() => document.querySelectorAll("div.mermaid").length === 1 && !document.querySelector("pre.mermaid"));
      assert.equal(await page.locator("h1").textContent(), item.title);
      assert.equal(await page.locator(".docs-evidence").count(), 0);
      assert.ok(await page.locator(`a[href*='labs/${slug}/']`).count() > 0);
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), `${slug} overflows at ${width}px`);
      assert.equal(errors.length, 0, errors.join("\n"));
      await context.close();
    }
  }
});


test("sidebar groups collapse with the keyboard and pagination links follow the current article", async () => {
  const {context, page, errors} = await pageAt("/appsec/ai-agent-security/");
  const current = page.locator("#docs-navigation a[aria-current='page']");
  assert.equal(await current.count(), 1);
  assert.equal(await current.textContent(), catalog.research.find(item => item.id === "ai-agent-security").navTitle);
  const group = current.locator("xpath=ancestor::details[1]");
  const summary = group.locator(":scope > summary");
  assert.equal(await group.getAttribute("open"), null);
  assert.equal(await current.isVisible(), false);
  await summary.focus();
  await page.keyboard.press("Enter");
  assert.equal(await current.isVisible(), true);
  await page.keyboard.press("Enter");
  assert.equal(await group.getAttribute("open"), null);
  assert.equal(await current.isVisible(), false);
  const next = page.locator(".md-footer__link--next");
  const nextUrl = new URL(await next.getAttribute("href"), page.url()).pathname;
  assert.ok(await page.locator(".md-footer__link--prev").count() === 1);
  await next.click();
  assert.equal(new URL(page.url()).pathname, nextUrl);
  const previousUrl = new URL(await page.locator(".md-footer__link--prev").getAttribute("href"), page.url()).pathname;
  assert.equal(previousUrl, "/appsec/ai-agent-security/");
  assert.equal(errors.length, 0, errors.join("\n"));
  await context.close();
});

test("mobile menu and search are keyboard operable", async () => {
  const {context, page, errors} = await pageAt("/appsec/ai-agent-security/", {width: 390, height: 844});
  const menu = page.locator(".docs-menu");
  await menu.focus();
  await page.keyboard.press("Enter");
  assert.equal(await menu.getAttribute("aria-expanded"), "true");
  assert.equal(await page.locator("#__drawer").isChecked(), true);
  assert.equal(await page.locator("#docs-navigation details[open]").count(), 0);
  await page.locator(".docs-nav-heading").filter({hasText: "Application Security"}).click();
  assert.equal(await page.locator("#docs-navigation a[aria-current='page']").isVisible(), true);
  await page.keyboard.press("Escape");
  assert.equal(await menu.getAttribute("aria-expanded"), "false");
  assert.equal(await menu.evaluate(element => element === document.activeElement), true);
  await page.keyboard.press("Control+k");
  assert.equal(await page.locator("#__search").isChecked(), true);
  await page.keyboard.press("Escape");
  assert.equal(errors.length, 0, errors.join("\n"));
  await context.close();
});

test("interface colors are neutral in both themes", async () => {
  for (const url of ["/", "/appsec/ai-agent-security/", "/labs/ai-agent-security/", "/scripts/devsecops/"]) {
    const {context, page} = await pageAt(url);
    for (const scheme of ["default", "slate"]) {
      await page.locator("body").evaluate((body, value) => body.setAttribute("data-md-color-scheme", value), scheme);
      const colored = await page.locator(".md-header, .docs-brand, .md-search__form, .md-sidebar--primary, .docs-nav-heading, .md-nav__link, .docs-card, .docs-button, .docs-action, .docs-key-takeaway, .md-footer, .md-footer__link, .md-option, .md-typeset table:not([class]) td").evaluateAll(elements => elements.flatMap(element => {
        const styles = getComputedStyle(element);
        return ["color", "backgroundColor", "borderTopColor"].flatMap(property => {
          const value = styles[property];
          const rgb = value.match(/^rgba?\((\d+), (\d+), (\d+)/);
          return rgb && (rgb[1] !== rgb[2] || rgb[2] !== rgb[3]) ? [`${element.className}: ${property}=${value}`] : [];
        });
      }));
      assert.deepEqual(colored, [], `${url} ${scheme}`);
      assert.equal(await page.locator("body").evaluate(body => getComputedStyle(body).backgroundColor), scheme === "slate" ? "rgb(0, 0, 0)" : "rgb(255, 255, 255)");
    }
    await context.close();
  }
});
