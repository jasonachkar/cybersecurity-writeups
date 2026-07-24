// Rendered-browser layout assertions for the responsive documentation shell.
// This is deliberately not a "does the class exist" test: every check below reads
// real computed styles / bounding boxes / DOM order from a live Playwright page,
// the same way a human resizing a browser window would judge the layout.
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import {chromium} from "playwright";
import {buildProvenance, writeQaReport, root} from "./qa-provenance.mjs";

const types = {
  ".html": "text/html", ".css": "text/css", ".js": "text/javascript", ".mjs": "text/javascript",
  ".json": "application/json", ".png": "image/png", ".svg": "image/svg+xml", ".woff2": "font/woff2",
  ".woff": "font/woff", ".ico": "image/x-icon", ".xml": "application/xml", ".gz": "application/gzip"
};

const server = http.createServer((request, response) => {
  const clean = decodeURIComponent(request.url.split(/[?#]/)[0]);
  let file = clean === "/" ? "index.html" : clean.replace(/^\//, "");
  if (file.endsWith("/")) file += "index.html";
  const target = path.join(root, file);
  if (!target.startsWith(root) || !fs.existsSync(target) || fs.statSync(target).isDirectory()) {
    response.writeHead(404);
    response.end("not found");
    return;
  }
  response.writeHead(200, {"content-type": types[path.extname(target).toLowerCase()] || "application/octet-stream"});
  response.end(fs.readFileSync(target));
});
await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
const {port} = server.address();
const base = `http://127.0.0.1:${port}`;

const browser = await chromium.launch();
const failures = [];
const checks = [];

function record(name, condition, detail) {
  checks.push({name, passed: Boolean(condition), detail: detail ?? null});
  if (!condition) failures.push(detail ? `${name}: ${detail}` : name);
}

async function newPage(viewport, scheme) {
  const context = await browser.newContext({
    viewport,
    colorScheme: scheme === "dark" ? "dark" : "light"
  });
  await context.addInitScript((paletteScheme) => {
    window.localStorage.setItem("/.__palette", JSON.stringify({index: paletteScheme === "dark" ? 1 : 0}));
  }, scheme);
  const page = await context.newPage();
  return {context, page};
}

async function gotoPage(page, url, scheme) {
  await page.goto(`${base}${url}`, {waitUntil: "load"});
  await page.evaluate((paletteScheme) => {
    document.body?.setAttribute("data-md-color-scheme", paletteScheme === "dark" ? "slate" : "default");
  }, scheme);
  await page.waitForTimeout(100);
}

const ARTICLE_URL = "/appsec/ai-agent-security/";
const NARROW_VIEWPORTS = [
  {name: "390x844", width: 390, height: 844},
  {name: "1024x768", width: 1024, height: 768}
];
const WIDE_VIEWPORTS = [
  {name: "1280x800", width: 1280, height: 800},
  {name: "1440x900", width: 1440, height: 900}
];
const FOOTER_URLS = ["/", ARTICLE_URL, "/docs/research-audit/content-inventory/", "/404.html"];

// --- Narrow viewports: inline TOC must be reachable without scrolling past the article. ---
for (const viewport of NARROW_VIEWPORTS) {
  for (const scheme of ["light", "dark"]) {
    const {context, page} = await newPage(viewport, scheme);
    await gotoPage(page, ARTICLE_URL, scheme);
    const label = `narrow ${viewport.name} ${scheme} ${ARTICLE_URL}`;

    const state = await page.evaluate(() => {
      const inlineToc = document.querySelector(".docs-inline-toc");
      const rightToc = document.querySelector(".docs-right-toc");
      const intro = document.querySelector(".md-content__inner > p");
      const inlineRect = inlineToc ? inlineToc.getBoundingClientRect() : null;
      const rightRect = rightToc ? rightToc.getBoundingClientRect() : null;
      const isVisible = (rect, el) => Boolean(el) && rect.width > 0 && rect.height > 0 && getComputedStyle(el).display !== "none";
      const beforeIntro = Boolean(
        inlineToc && intro &&
        (inlineToc.compareDocumentPosition(intro) & Node.DOCUMENT_POSITION_FOLLOWING)
      );
      return {
        hasInlineToc: Boolean(inlineToc),
        inlineVisible: isVisible(inlineRect, inlineToc),
        inlineOpen: inlineToc ? inlineToc.open : null,
        beforeIntro,
        rightTocVisible: isVisible(rightRect, rightToc),
        docScrollWidth: document.documentElement.scrollWidth,
        docClientWidth: document.documentElement.clientWidth,
        copyrightCount: document.querySelectorAll(".docs-footer__copyright").length
      };
    });

    record(`${label}: inline TOC exists`, state.hasInlineToc);
    record(`${label}: inline TOC visible`, state.inlineVisible);
    record(`${label}: inline TOC initially closed`, state.inlineOpen === false, `open=${state.inlineOpen}`);
    record(`${label}: inline TOC precedes intro paragraph in DOM order`, state.beforeIntro);
    record(`${label}: desktop TOC not visible`, !state.rightTocVisible);
    record(`${label}: no horizontal document overflow`, state.docScrollWidth <= state.docClientWidth + 1,
      `scrollWidth=${state.docScrollWidth} clientWidth=${state.docClientWidth}`);
    record(`${label}: exactly one visible copyright line`, state.copyrightCount === 1, `count=${state.copyrightCount}`);

    await context.close();
  }
}

// --- Wide viewports: desktop TOC must be the one showing, positioned clear of the article. ---
for (const viewport of WIDE_VIEWPORTS) {
  for (const scheme of ["light", "dark"]) {
    const {context, page} = await newPage(viewport, scheme);
    await gotoPage(page, ARTICLE_URL, scheme);
    const label = `wide ${viewport.name} ${scheme} ${ARTICLE_URL}`;

    const state = await page.evaluate(() => {
      const article = document.querySelector(".md-content");
      const toc = document.querySelector(".docs-right-toc");
      const inlineToc = document.querySelector(".docs-inline-toc");
      const leftNav = document.querySelector(".docs-left-nav");
      const isVisible = (el) => {
        if (!el) return false;
        const rect = el.getBoundingClientRect();
        return rect.width > 0 && rect.height > 0 && getComputedStyle(el).display !== "none";
      };
      const articleRect = article ? article.getBoundingClientRect() : null;
      const tocRect = toc ? toc.getBoundingClientRect() : null;
      const leftNavRect = leftNav ? leftNav.getBoundingClientRect() : null;
      return {
        tocVisible: isVisible(toc),
        inlineVisible: isVisible(inlineToc),
        leftNavVisible: isVisible(leftNav),
        articleRight: articleRect ? articleRect.right : null,
        tocLeft: tocRect ? tocRect.left : null,
        leftNavRight: leftNavRect ? leftNavRect.right : null,
        articleLeft: articleRect ? articleRect.left : null,
        copyrightCount: document.querySelectorAll(".docs-footer__copyright").length
      };
    });

    record(`${label}: desktop TOC visible`, state.tocVisible);
    record(`${label}: inline TOC not visible`, !state.inlineVisible);
    record(`${label}: left nav visible`, state.leftNavVisible);
    if (state.tocVisible) {
      record(`${label}: desktop TOC does not overlap article`, state.tocLeft >= state.articleRight - 1,
        `tocLeft=${state.tocLeft} articleRight=${state.articleRight}`);
    }
    if (state.leftNavVisible) {
      record(`${label}: left nav does not overlap article`, state.leftNavRight <= state.articleLeft + 1,
        `leftNavRight=${state.leftNavRight} articleLeft=${state.articleLeft}`);
    }
    record(`${label}: exactly one visible copyright line`, state.copyrightCount === 1, `count=${state.copyrightCount}`);

    await context.close();
  }
}

// --- Scrollspy: the active TOC entry must persist through a long section, not clear
// itself out once the heading has scrolled out of a narrow observation zone. ---
{
  const {context, page} = await newPage({width: 1440, height: 900}, "light");
  await gotoPage(page, ARTICLE_URL, "light");
  const label = "scrollspy 1440x900 light";

  const sections = await page.evaluate(() => {
    // Only headings the desktop TOC actually links to (matches what docs-ui.js's
    // scrollspy observes) — the h2-scan in maintain-gh-pages.mjs caps at 16 and
    // skips duplicate ids, so this can be a strict subset of every <h2> in the page.
    const headings = [...document.querySelectorAll(".docs-right-toc nav a[href^='#']")]
      .map(link => document.getElementById(link.getAttribute("href").slice(1)))
      .filter(Boolean);
    return headings.map((h, index, arr) => {
      const next = arr[index + 1];
      return {
        id: h.id,
        top: h.getBoundingClientRect().top + window.scrollY,
        nextTop: next ? next.getBoundingClientRect().top + window.scrollY : null
      };
    });
  });
  const longSection = sections.find(s => s.nextTop !== null && s.nextTop - s.top > 600);

  if (!longSection) {
    record(`${label}: found a section long enough to test scrollspy persistence`, false,
      "no section exceeded 600px; scrollspy persistence not exercised");
  } else {
    record(`${label}: found a section long enough to test scrollspy persistence`, true);

    // Scroll well below the heading itself, but comfortably before the next one.
    await page.evaluate((y) => window.scrollTo(0, y), longSection.top + 300);
    await page.waitForTimeout(150);
    const midSectionActive = await page.evaluate((id) => {
      const link = document.querySelector(`.docs-right-toc nav a[href="#${id}"]`);
      return link ? link.getAttribute("data-docs-toc-active") : null;
    }, longSection.id);
    record(`${label}: active link persists mid-section (not cleared)`, midSectionActive === "true",
      `data-docs-toc-active=${midSectionActive}`);

    await page.evaluate((y) => window.scrollTo(0, y), longSection.nextTop + 10);
    await page.waitForTimeout(150);
    const afterNextActive = await page.evaluate((id) => {
      const link = document.querySelector(`.docs-right-toc nav a[href="#${id}"]`);
      return link ? link.getAttribute("data-docs-toc-active") : null;
    }, longSection.id);
    record(`${label}: active link changes after entering the next section`, afterNextActive !== "true",
      `previous section data-docs-toc-active=${afterNextActive}`);
  }

  await context.close();
}

// --- Footer: no duplicate Material footer-meta block, exactly one copyright line. ---
for (const url of FOOTER_URLS) {
  const {context, page} = await newPage({width: 1440, height: 900}, "light");
  await gotoPage(page, url, "light");
  const label = `footer ${url}`;

  const state = await page.evaluate(() => ({
    footerMetaCount: document.querySelectorAll(".md-footer-meta").length,
    copyrightCount: document.querySelectorAll(".docs-footer__copyright").length,
    footerCount: document.querySelectorAll("footer.md-footer").length
  }));
  record(`${label}: no legacy .md-footer-meta block`, state.footerMetaCount === 0, `count=${state.footerMetaCount}`);
  record(`${label}: exactly one visible copyright line`, state.copyrightCount === 1, `count=${state.copyrightCount}`);
  record(`${label}: exactly one <footer class="md-footer">`, state.footerCount === 1, `count=${state.footerCount}`);

  await context.close();
}

await browser.close();
server.close();

const passed = failures.length === 0;
const provenance = buildProvenance({
  command: "npm run verify:ui",
  toolVersions: {playwright: JSON.parse(fs.readFileSync(new URL("../node_modules/playwright/package.json", import.meta.url), "utf8")).version},
  result: passed ? "passed" : "failed"
});
const report = {
  ...provenance,
  totalChecks: checks.length,
  failedChecks: failures.length,
  checks,
  failures
};
writeQaReport("ui-layout-report.json", report);

console.log(`UI layout audit: ${checks.length} checks, ${failures.length} failed.`);
if (failures.length) {
  for (const failure of failures) console.log(`- FAIL ${failure}`);
  process.exit(1);
}
console.log("All responsive documentation-shell layout assertions passed.");
