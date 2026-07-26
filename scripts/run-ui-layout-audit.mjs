// Rendered-browser layout assertions for the responsive documentation shell.
// This is deliberately not a "does the class exist" test: every check below reads
// real computed styles / bounding boxes / DOM order from a live Playwright page,
// the same way a human resizing a browser window would judge the layout.
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import {chromium} from "playwright";
import {buildProvenance, writeQaReport, root} from "./qa-provenance.mjs";
import {LABS} from "../labs/catalog.mjs";

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
const FOOTER_URLS = ["/", ARTICLE_URL, "/scripts/", "/404.html"];

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

// --- Scripts: source viewer renders before the explanation, tabs/copy/expand work. ---
{
  const {context, page} = await newPage({width: 1280, height: 900}, "light");
  await gotoPage(page, "/scripts/cloud-security/", "light");
  const label = "scripts source-viewer /scripts/cloud-security/";

  const order = await page.evaluate(() => {
    const section = document.getElementById("k8s-rbac-auditor");
    if (!section) return null;
    const viewer = section.querySelector(".docs-source-viewer");
    const heading = [...section.querySelectorAll("h3")].find(h => h.textContent.trim() === "What it does");
    if (!viewer || !heading) return null;
    return Boolean(viewer.compareDocumentPosition(heading) & Node.DOCUMENT_POSITION_FOLLOWING);
  });
  record(`${label}: script section exists with a source viewer and "What it does"`, order !== null);
  record(`${label}: source viewer precedes "What it does"`, order === true);

  const noGithubLink = await page.evaluate(() => {
    const section = document.getElementById("k8s-rbac-auditor");
    return section ? !section.innerHTML.includes("github.com/jasonachkar/cybersecurity-writeups/blob") : null;
  });
  record(`${label}: does not depend on a GitHub link to show source`, noGithubLink === true);

  // Tabs: switch to the "Tests" tab and confirm the panel + toolbar title change.
  const tabsWork = await page.evaluate(() => {
    const viewer = document.getElementById("source-k8s-rbac-auditor");
    const testsTab = viewer.querySelector('[data-source-tab][data-index="1"]');
    testsTab.click();
    const panel0 = viewer.querySelector('[data-source-panel][data-index="0"]');
    const panel1 = viewer.querySelector('[data-source-panel][data-index="1"]');
    return {
      tab1Selected: testsTab.getAttribute("aria-selected") === "true",
      panel0Hidden: panel0.hasAttribute("hidden"),
      panel1Visible: !panel1.hasAttribute("hidden"),
      title: viewer.querySelector(".docs-source-viewer__toolbar-title").textContent
    };
  });
  record(`${label}: clicking a file tab selects it`, tabsWork.tab1Selected);
  record(`${label}: switching tabs hides the other panel`, tabsWork.panel0Hidden && tabsWork.panel1Visible);
  record(`${label}: toolbar title follows the active tab`, tabsWork.title.includes("auditor_test.go"), `title=${tabsWork.title}`);

  // Copy: stub the clipboard (Playwright contexts don't grant clipboard-write by default).
  await page.evaluate(() => {
    window.__copied = null;
    navigator.clipboard.writeText = (text) => { window.__copied = text; return Promise.resolve(); };
  });
  const copyResult = await page.evaluate(() => {
    const viewer = document.getElementById("source-k8s-rbac-auditor");
    viewer.querySelector("[data-copy-source]").click();
    return true;
  });
  await page.waitForTimeout(50);
  const copiedText = await page.evaluate(() => window.__copied);
  record(`${label}: copy button copies the visible file's source`, Boolean(copyResult) && typeof copiedText === "string" && copiedText.length > 0);

  // Expand: toggling sets aria-expanded and removes the height cap class.
  const expandState = await page.evaluate(() => {
    const viewer = document.getElementById("source-k8s-rbac-auditor");
    const button = viewer.querySelector("[data-expand-source]");
    button.click();
    const code = viewer.querySelector(".docs-source-viewer__code");
    return {expanded: button.getAttribute("aria-expanded"), hasClass: code.classList.contains("docs-source-expanded")};
  });
  record(`${label}: expand button sets aria-expanded=true`, expandState.expanded === "true");
  record(`${label}: expand button removes the height cap`, expandState.hasClass === true);

  await context.close();
}

// --- Scripts mobile toolbar: buttons/tabs stay usable at 390px. ---
{
  const {context, page} = await newPage({width: 390, height: 844}, "light");
  await gotoPage(page, "/scripts/cloud-security/", "light");
  const label = "scripts mobile toolbar 390x844";
  const state = await page.evaluate(() => {
    const viewer = document.getElementById("source-k8s-rbac-auditor");
    const toolbar = viewer.querySelector(".docs-source-viewer__toolbar");
    const buttons = [...viewer.querySelectorAll(".docs-source-viewer__button")];
    return {
      noOverflow: document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1,
      toolbarWidth: toolbar.getBoundingClientRect().width,
      docWidth: document.documentElement.clientWidth,
      buttonHeights: buttons.map(b => b.getBoundingClientRect().height)
    };
  });
  record(`${label}: no page-level horizontal overflow`, state.noOverflow);
  record(`${label}: toolbar fits within the viewport`, state.toolbarWidth <= state.docWidth + 1,
    `toolbarWidth=${state.toolbarWidth} docWidth=${state.docWidth}`);
  record(`${label}: action buttons meet a ~44px touch target`, state.buttonHeights.every(h => h >= 40),
    `heights=${state.buttonHeights.join(",")}`);
  await context.close();
}

// --- Labs: every maintained lab shows its implementation near the top, before the
// long explanation, with its run commands — not appended after references. ---
for (const lab of LABS) {
  const {context, page} = await newPage({width: 1280, height: 900}, "light");
  await gotoPage(page, `/${lab.page.replace(/index\.html$/, "")}`, "light");
  const label = `lab implementation /${lab.page.replace(/index\.html$/, "")}`;

  const state = await page.evaluate(() => {
    const article = document.querySelector(".md-content__inner");
    const viewer = article ? article.querySelector(".docs-source-viewer") : null;
    const h1 = article ? article.querySelector("h1") : null;
    const headings = article ? [...article.querySelectorAll("h2")] : [];
    const implIndex = headings.findIndex(h => h.id === "implementation");
    return {
      hasViewer: Boolean(viewer),
      viewerAfterH1: Boolean(viewer && h1 && (h1.compareDocumentPosition(viewer) & Node.DOCUMENT_POSITION_FOLLOWING)),
      implementationPosition: implIndex,
      totalH2: headings.length,
      hasRunCommands: Boolean(article && article.querySelector(".docs-run-commands"))
    };
  });
  record(`${label}: renders an implementation source viewer`, state.hasViewer);
  record(`${label}: viewer appears after the H1 (near the top)`, state.viewerAfterH1);
  record(`${label}: "Implementation" heading is near the top, not appended at the end`,
    state.implementationPosition !== -1 && state.implementationPosition <= 1,
    `position=${state.implementationPosition} of ${state.totalH2}`);
  record(`${label}: shows its run command(s)`, state.hasRunCommands);

  await context.close();
}

// --- Breadcrumbs: click every ancestor and verify the resulting pathname, for a
// deep page (AZ-900 domain) and one representative page per top-level section. ---
const BREADCRUMB_ROUTES = [
  {
    start: "/docs/certification-notes/az-900/domain-1-concepts/",
    clicks: [
      {text: "AZ-900", expect: "/docs/certification-notes/az-900/"},
      {text: "Study notes", expect: "/study-notes/"},
      {text: "Home", expect: "/"}
    ]
  },
  {
    start: "/cloud-security/iam-at-scale/",
    clicks: [
      {text: "Cloud Security", expect: "/cloud-security/"},
      {text: "Research", expect: "/research/"},
      {text: "Home", expect: "/"}
    ]
  },
  {
    start: "/labs/secure-cicd/",
    clicks: [
      {text: "Labs", expect: "/labs/"},
      {text: "Home", expect: "/"}
    ]
  },
  {
    start: "/scripts/cloud-security/",
    clicks: [
      {text: "Scripts", expect: "/scripts/"},
      {text: "Home", expect: "/"}
    ]
  }
];

for (const route of BREADCRUMB_ROUTES) {
  const {context, page} = await newPage({width: 1280, height: 900}, "light");
  await gotoPage(page, route.start, "light");
  const label = `breadcrumb clicks from ${route.start}`;
  let currentUrl = route.start;
  for (const step of route.clicks) {
    const link = page.locator(".docs-breadcrumbs a", {hasText: step.text}).first();
    const exists = (await link.count()) > 0;
    if (!exists) {
      record(`${label}: breadcrumb link "${step.text}" exists and is clickable`, false, `not found from ${currentUrl}`);
      break;
    }
    // Playwright's own click() waits out the navigation it causes; driving the
    // click through page.evaluate() instead raced the page tearing down its
    // JS execution context mid-navigation and crashed the whole run.
    await Promise.all([page.waitForLoadState("load"), link.click()]);
    const pathname = await page.evaluate(() => location.pathname);
    record(`${label}: clicking "${step.text}" navigates to ${step.expect}`, pathname === step.expect, `got ${pathname}`);
    currentUrl = step.expect;
  }
  await context.close();
}

// --- Mobile navigation drawer: open, focus, Escape close, focus return, overlay close. ---
{
  const {context, page} = await newPage({width: 390, height: 844}, "light");
  await gotoPage(page, "/", "light");
  const label = "mobile drawer 390x844";

  const trigger = page.locator('label.md-header__button[for="__drawer"]');
  await trigger.click();
  const openState = await page.evaluate(() => ({
    checked: document.getElementById("__drawer").checked,
    drawerVisible: (() => {
      const rect = document.querySelector(".docs-left-nav").getBoundingClientRect();
      return rect.width > 0 && rect.left < window.innerWidth;
    })(),
    bodyLocked: getComputedStyle(document.body).overflow === "hidden"
  }));
  record(`${label}: opening the trigger checks the drawer toggle`, openState.checked);
  record(`${label}: drawer becomes visible on open`, openState.drawerVisible);
  record(`${label}: background scroll is locked while open`, openState.bodyLocked);

  await page.keyboard.press("Escape");
  const afterEscape = await page.evaluate(() => document.getElementById("__drawer").checked);
  record(`${label}: Escape closes the drawer`, afterEscape === false);
  const focusReturned = await page.evaluate(() =>
    document.activeElement === document.querySelector('label.md-header__button[for="__drawer"]'));
  record(`${label}: focus returns to the trigger after Escape`, focusReturned);

  // Overlay click also closes it.
  await trigger.click();
  await page.evaluate(() => document.querySelector(".md-overlay").click());
  const afterOverlay = await page.evaluate(() => document.getElementById("__drawer").checked);
  record(`${label}: clicking the overlay closes the drawer`, afterOverlay === false);

  const widthOk = await page.evaluate(() => {
    const rect = document.querySelector(".docs-left-nav").getBoundingClientRect();
    return rect.width <= window.innerWidth;
  });
  record(`${label}: drawer never exceeds the viewport width`, widthOk);

  await context.close();
}

// --- Mobile sweep: no page-level horizontal overflow across the required matrix. ---
const MOBILE_SWEEP_VIEWPORTS = [
  {name: "320x568", width: 320, height: 568},
  {name: "360x800", width: 360, height: 800},
  {name: "390x844", width: 390, height: 844},
  {name: "412x915", width: 412, height: 915},
  {name: "768x1024", width: 768, height: 1024},
  {name: "1024x768", width: 1024, height: 768},
  {name: "1280x800", width: 1280, height: 800},
  {name: "1440x900", width: 1440, height: 900}
];
const MOBILE_SWEEP_PAGES = [
  "/", ARTICLE_URL, "/research/", "/scripts/", "/scripts/cloud-security/", "/scripts/devsecops/",
  "/labs/secure-cicd/", "/labs/postgresql-rls/", "/labs/kubernetes-security/", "/labs/azure-landing-zone/",
  "/docs/certification-notes/az-900/", "/docs/certification-notes/az-900/domain-1-concepts/",
  "/about/", "/404.html"
];
for (const viewport of MOBILE_SWEEP_VIEWPORTS) {
  for (const scheme of ["light", "dark"]) {
    for (const url of MOBILE_SWEEP_PAGES) {
      const {context, page} = await newPage(viewport, scheme);
      await gotoPage(page, url, scheme);
      const label = `mobile sweep ${viewport.name} ${scheme} ${url}`;
      const state = await page.evaluate(() => ({
        scrollWidth: document.documentElement.scrollWidth,
        clientWidth: document.documentElement.clientWidth
      }));
      record(`${label}: no horizontal document overflow`, state.scrollWidth <= state.clientWidth + 1,
        `scrollWidth=${state.scrollWidth} clientWidth=${state.clientWidth}`);

      if (process.env.CAPTURE_UI_SCREENSHOTS === "1") {
        const dir = path.join(root, "qa-artifacts", "ui-screenshots", scheme, viewport.name);
        fs.mkdirSync(dir, {recursive: true});
        const safeName = url === "/" ? "home" : url.replace(/^\/|\/$/g, "").replace(/\//g, "_") || "home";
        await page.screenshot({path: path.join(dir, `${safeName}.png`), fullPage: true});
      }

      await context.close();
    }
  }
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
