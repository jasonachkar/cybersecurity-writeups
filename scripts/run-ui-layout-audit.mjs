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
import {SCRIPTS} from "./catalog.mjs";
import {resolveSourceLanguage} from "./source-languages.mjs";

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
  // Shiki-expanded catalogue pages can be several megabytes of static HTML; the
  // full screenshot matrix deliberately gives those deterministic local loads
  // more headroom than Playwright's generic 30-second navigation default.
  await page.goto(`${base}${url}`, {waitUntil: "load", timeout: 60000});
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

// --- Search: generated category/type metadata sits between a concise title and
// teaser while Material's keyboard-navigation behavior remains available. ---
{
  const {context, page} = await newPage({width: 1440, height: 900}, "light");
  await gotoPage(page, "/", "light");
  const input = page.locator('[data-md-component="search-query"]');
  await input.click();
  await input.pressSequentially("secure cicd", {delay: 20});
  await page.locator(".md-search-result__article").first().waitFor({state: "visible", timeout: 10000});
  const state = await page.evaluate(() => {
    const article = document.querySelector(".md-search-result__article");
    const title = article?.querySelector("h1");
    const metadata = article?.querySelector(":scope > .md-tags");
    return {
      count: document.querySelectorAll(".md-search-result__article").length,
      title: title?.textContent.trim(),
      metadata: metadata?.textContent.trim(),
      metadataAfterTitle: Boolean(title && metadata && title.nextElementSibling === metadata),
      articleHeight: article?.getBoundingClientRect().height,
      articleMaxHeight: article ? parseFloat(getComputedStyle(article).maxHeight) : null
    };
  });
  record("search results: relevant results render", state.count > 0 && /secure|ci\/cd/i.test(state.title || ""), JSON.stringify(state));
  record("search results: category/type metadata follows title", state.metadataAfterTitle && / · /.test(state.metadata || ""), JSON.stringify(state));
  record("search results: teaser remains visually bounded", state.articleHeight <= state.articleMaxHeight + 1, JSON.stringify(state));
  const readKeyboardTarget = () => page.evaluate(() => {
    const active = document.activeElement;
    return {
      matched: Boolean(active && active.closest(".md-search-result") && active.matches("a, summary, [tabindex]")),
      tag: active?.tagName || null,
      className: active?.className || null
    };
  });
  await input.press("ArrowDown");
  await page.waitForTimeout(250);
  let keyboardTarget = await readKeyboardTarget();
  if (!keyboardTarget.matched) {
    await input.focus();
    await input.press("ArrowDown");
    await page.waitForTimeout(500);
    keyboardTarget = await readKeyboardTarget();
  }
  record("search results: ArrowDown moves keyboard focus into results", keyboardTarget.matched, JSON.stringify(keyboardTarget));
  await context.close();
}

// --- Generated source contract: every catalogue language is highlighted or uses
// its one explicit fallback, and every tracked path appears in its generated page. ---
for (const owner of [
  ...SCRIPTS.map(script => ({page: `scripts/${script.category}/index.html`, id: script.slug, sourceFiles: script.sourceFiles})),
  ...LABS.map(lab => ({page: lab.page, id: lab.slug, sourceFiles: lab.sourceFiles}))
]) {
  const html = fs.readFileSync(path.join(root, owner.page), "utf8");
  for (const sourceFile of owner.sourceFiles) {
    const language = resolveSourceLanguage(sourceFile.language);
    const escapedPath = sourceFile.path.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const panelMatch = html.match(new RegExp(`<div[^>]+data-source-path="${escapedPath}"[^>]+data-source-highlighter="([^"]+)"[\\s\\S]*?<\\/div>`));
    const expectedHighlighter = language.mode === "shiki" ? "shiki" : "plaintext";
    record(`source generation ${owner.id}: ${sourceFile.path} is rendered`, Boolean(panelMatch));
    record(`source generation ${owner.id}: ${sourceFile.path} uses ${expectedHighlighter}`,
      panelMatch?.[1] === expectedHighlighter, `got ${panelMatch?.[1] || "no panel"}`);
    if (language.mode === "shiki") {
      record(`source generation ${owner.id}: ${sourceFile.path} contains themed Shiki tokens`,
        Boolean(panelMatch && /--shiki-light:[^;"']+;--shiki-dark:/.test(panelMatch[0])));
    }
  }
}

// --- Source viewer: progressive source, metadata, tabs, copy, wrap, line numbers,
// and short/long-file behavior are verified against real tracked files. ---
{
  const {context, page} = await newPage({width: 1280, height: 900}, "light");
  await gotoPage(page, "/labs/secure-cicd/", "light");
  const label = "source-viewer /labs/secure-cicd/";

  const order = await page.evaluate(() => {
    const section = document.querySelector(".md-content__inner");
    if (!section) return null;
    const viewer = section.querySelector(".docs-source-viewer");
    const heading = [...section.querySelectorAll("h2")].find(h => h.id === "prerequisites-and-run-commands");
    if (!viewer || !heading) return null;
    return Boolean(viewer.compareDocumentPosition(heading) & Node.DOCUMENT_POSITION_FOLLOWING);
  });
  record(`${label}: script section exists with a source viewer and "What it does"`, order !== null);
  record(`${label}: source viewer precedes "What it does"`, order === true);

  const noGithubLink = await page.evaluate(() => {
    const section = document.querySelector(".md-content__inner");
    return section ? !section.innerHTML.includes("github.com/jasonachkar/cybersecurity-writeups/blob") : null;
  });
  record(`${label}: does not depend on a GitHub link to show source`, noGithubLink === true);

  const primarySource = fs.readFileSync(path.join(root, "labs/secure-cicd/gate.js"), "utf8").replace(/\r\n/g, "\n");
  const longSource = fs.readFileSync(path.join(root, "labs/secure-cicd/tests/policy-tests.js"), "utf8").replace(/\r\n/g, "\n");
  const initial = await page.evaluate(() => {
    const viewer = document.getElementById("source-secure-cicd");
    const panel = viewer.querySelector('[data-source-panel][data-index="0"]');
    const pre = panel.querySelector("pre");
    const firstLine = panel.querySelector(".line");
    return {
      source: panel.querySelector("code").textContent,
      filename: viewer.querySelector("[data-source-active-filename]").textContent,
      language: viewer.querySelector("[data-source-active-language]").textContent,
      lines: viewer.querySelector("[data-source-active-lines]").textContent,
      path: viewer.querySelector("[data-source-active-path]").textContent,
      noVerticalScroll: pre.scrollHeight <= pre.clientHeight + 1,
      expandHidden: viewer.querySelector("[data-expand-source]").hidden,
      lineNumber: getComputedStyle(firstLine, "::before").content,
      lineNumberSelectable: getComputedStyle(firstLine, "::before").userSelect
    };
  });
  record(`${label}: primary rendered text exactly matches tracked source`, initial.source === primarySource);
  record(`${label}: compact metadata is source-derived`, initial.filename === "gate.js" && initial.language === "JavaScript" && initial.lines === "46 lines" && initial.path === "labs/secure-cicd/gate.js");
  record(`${label}: short source has no internal vertical scrollbar`, initial.noVerticalScroll);
  record(`${label}: short source has no Expand action`, initial.expandHidden);
  record(`${label}: line numbers render through non-selectable generated content`, /counter\(docs-source-line\)|"1"/.test(initial.lineNumber) && initial.lineNumberSelectable === "none",
    `content=${initial.lineNumber} userSelect=${initial.lineNumberSelectable}`);

  const tabsWork = await page.evaluate(() => {
    const viewer = document.getElementById("source-secure-cicd");
    const testsTab = viewer.querySelector('[data-source-tab][data-index="2"]');
    testsTab.click();
    const panel0 = viewer.querySelector('[data-source-panel][data-index="0"]');
    const panel1 = viewer.querySelector('[data-source-panel][data-index="2"]');
    return {
      tab1Selected: testsTab.getAttribute("aria-selected") === "true",
      panel0Hidden: panel0.hasAttribute("hidden"),
      panel1Visible: !panel1.hasAttribute("hidden"),
      title: viewer.querySelector("[data-source-active-filename]").textContent,
      language: viewer.querySelector("[data-source-active-language]").textContent,
      lines: viewer.querySelector("[data-source-active-lines]").textContent,
      path: viewer.querySelector("[data-source-active-path]").textContent,
      expandVisible: !viewer.querySelector("[data-expand-source]").hidden
    };
  });
  record(`${label}: clicking a file tab selects it`, tabsWork.tab1Selected);
  record(`${label}: switching tabs hides the other panel`, tabsWork.panel0Hidden && tabsWork.panel1Visible);
  record(`${label}: toolbar metadata follows the active tab`, tabsWork.title === "policy-tests.js" && tabsWork.language === "JavaScript" && tabsWork.lines === "201 lines" && tabsWork.path.endsWith("policy-tests.js"));
  record(`${label}: Expand appears for the active long file`, tabsWork.expandVisible);

  // Copy: stub the clipboard (Playwright contexts don't grant clipboard-write by default).
  await page.evaluate(() => {
    window.__copied = null;
    navigator.clipboard.writeText = (text) => { window.__copied = text; return Promise.resolve(); };
  });
  const copyResult = await page.evaluate(() => {
    const viewer = document.getElementById("source-secure-cicd");
    viewer.querySelector("[data-copy-source]").click();
    return true;
  });
  await page.waitForTimeout(50);
  const copiedText = await page.evaluate(() => window.__copied);
  record(`${label}: copy button copies the active raw file exactly`, Boolean(copyResult) && copiedText === longSource);

  const expandState = await page.evaluate(() => {
    const viewer = document.getElementById("source-secure-cicd");
    const button = viewer.querySelector("[data-expand-source]");
    const panel = viewer.querySelector('[data-source-panel][data-index="2"]');
    const code = panel.querySelector(".docs-source-viewer__code");
    const collapsed = {clientHeight: code.clientHeight, scrollHeight: code.scrollHeight};
    button.click();
    const expanded = {clientHeight: code.clientHeight, scrollHeight: code.scrollHeight};
    viewer.querySelector('[data-source-tab][data-index="0"]').click();
    const hiddenOnShort = button.hidden;
    viewer.querySelector('[data-source-tab][data-index="2"]').click();
    return {aria: button.getAttribute("aria-expanded"), collapsed, expanded, hiddenOnShort, restored: button.textContent};
  });
  record(`${label}: long source is capped initially`, expandState.collapsed.scrollHeight > expandState.collapsed.clientHeight + 1);
  record(`${label}: expand removes the cap and sets aria-expanded`, expandState.aria === "true" && expandState.expanded.clientHeight >= expandState.expanded.scrollHeight - 1);
  record(`${label}: expand state is active-file aware and restored`, expandState.hiddenOnShort && expandState.restored === "Collapse");

  const wrapState = await page.evaluate(() => {
    const viewer = document.getElementById("source-secure-cicd");
    const button = viewer.querySelector("[data-wrap-source]");
    const line = viewer.querySelector('[data-source-panel][data-index="2"] .line');
    const before = getComputedStyle(line).whiteSpace;
    button.click();
    const after = getComputedStyle(line).whiteSpace;
    viewer.querySelector('[data-source-tab][data-index="0"]').click();
    const persisted = getComputedStyle(viewer.querySelector('[data-source-panel][data-index="0"] .line')).whiteSpace;
    return {before, after, persisted, pressed: button.getAttribute("aria-pressed")};
  });
  record(`${label}: Wrap changes computed white-space and aria-pressed`, wrapState.before === "pre" && wrapState.after === "pre-wrap" && wrapState.pressed === "true", JSON.stringify(wrapState));
  record(`${label}: Wrap persists across file tabs`, wrapState.persisted === "pre-wrap");

  // Keyboard navigation exercises End, Home, and both arrows with roving focus.
  await page.locator('#source-secure-cicd-tab-0').focus();
  await page.keyboard.press("End");
  await page.keyboard.press("ArrowLeft");
  await page.keyboard.press("ArrowRight");
  await page.keyboard.press("Home");
  const keyboardState = await page.evaluate(() => ({
    selected: document.querySelector('#source-secure-cicd-tab-0').getAttribute("aria-selected"),
    focused: document.activeElement?.id,
    tabStops: [...document.querySelectorAll('#source-secure-cicd [role="tab"]')].filter(tab => tab.tabIndex === 0).length
  }));
  record(`${label}: Arrow/Home/End preserve roving tab semantics`, keyboardState.selected === "true" && keyboardState.focused === "source-secure-cicd-tab-0" && keyboardState.tabStops === 1, JSON.stringify(keyboardState));

  await context.close();
}

// JavaScript is enhancement only: the primary source remains visible and actions
// that cannot work are not presented as controls.
{
  const context = await browser.newContext({viewport: {width: 390, height: 844}, javaScriptEnabled: false});
  const page = await context.newPage();
  await page.goto(`${base}/labs/secure-cicd/`, {waitUntil: "load"});
  const state = await page.evaluate(() => {
    const viewer = document.getElementById("source-secure-cicd");
    return {
      primaryVisible: viewer.querySelector('[data-source-panel][data-index="0"]').getBoundingClientRect().height > 0,
      sourceLength: viewer.querySelector('[data-source-panel][data-index="0"] code').textContent.length,
      actionsDisplay: getComputedStyle(viewer.querySelector("[data-source-actions]")).display,
      tabsDisplay: getComputedStyle(viewer.querySelector("[role=tablist]")).display
    };
  });
  record("source-viewer progressive enhancement: primary source remains readable", state.primaryVisible && state.sourceLength > 0);
  record("source-viewer progressive enhancement: inactive controls stay hidden", state.actionsDisplay === "none" && state.tabsDisplay === "none", JSON.stringify(state));
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

// Structural alignment and breadcrumb presentation across representative content
// types, both palettes, and every requested documentation breakpoint.
const BREADCRUMB_GEOMETRY_PAGES = [
  "/appsec/ai-agent-security/",
  "/labs/secure-cicd/",
  "/scripts/devsecops/",
  "/docs/certification-notes/az-900/domain-1-concepts/"
];
for (const width of [375, 768, 1024, 1280, 1440]) {
  for (const scheme of ["light", "dark"]) {
    const {context, page} = await newPage({width, height: 900}, scheme);
    for (const url of BREADCRUMB_GEOMETRY_PAGES) {
      await gotoPage(page, url, scheme);
      const state = await page.evaluate(() => {
        const header = document.querySelector(".docs-article-header");
        const breadcrumbs = header?.querySelector(".docs-breadcrumbs");
        const h1 = header?.querySelector("h1");
        const current = breadcrumbs?.querySelector('[aria-current="page"]');
        const first = breadcrumbs?.querySelector("li:first-child");
        const breadcrumbRect = breadcrumbs?.getBoundingClientRect();
        const h1Rect = h1?.getBoundingClientRect();
        const currentRect = current?.getBoundingClientRect();
        const separator = first ? getComputedStyle(first, "::after") : null;
        return {
          headerContainsBoth: Boolean(header && breadcrumbs && h1),
          delta: breadcrumbRect && h1Rect ? Math.abs(breadcrumbRect.left - h1Rect.left) : null,
          noOverlap: breadcrumbRect && h1Rect ? breadcrumbRect.bottom <= h1Rect.top + 1 : false,
          noOverflow: document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1,
          currentIsLink: Boolean(current?.querySelector("a")),
          currentVisible: Boolean(currentRect && breadcrumbRect && currentRect.right <= breadcrumbRect.right + 1 && currentRect.left >= breadcrumbRect.left - 1),
          separatorContent: separator?.content,
          separatorTransform: separator?.transform
        };
      });
      const label = `breadcrumb geometry ${width}px ${scheme} ${url}`;
      record(`${label}: breadcrumb and H1 share article header`, state.headerContainsBoth);
      record(`${label}: left edges align within 1px`, state.delta !== null && state.delta <= 1, `delta=${state.delta}`);
      record(`${label}: breadcrumb does not overlap H1`, state.noOverlap);
      record(`${label}: no document overflow`, state.noOverflow);
      record(`${label}: current crumb is non-clickable and visible`, !state.currentIsLink && state.currentVisible, JSON.stringify(state));
      record(`${label}: separator is a presentational chevron`, state.separatorContent === '""' && state.separatorTransform !== "none", JSON.stringify(state));
    }
    await context.close();
  }
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

// --- Mobile-only polish fixes: each assertion here locks in a real defect found by
// manual screenshot inspection at 375-390px (not just "no page-level overflow"),
// so it cannot silently regress. ---
{
  const {context, page} = await newPage({width: 390, height: 844}, "light");
  await gotoPage(page, ARTICLE_URL, "light");
  const label = "mobile polish 390x844";

  // Material's own admonition `::before` icon targets any `.md-typeset summary`,
  // including this component's — it must stay suppressed, not just repainted.
  const tocIconHidden = await page.evaluate(() => {
    const summary = document.querySelector(".docs-inline-toc > summary");
    if (!summary) return null;
    return getComputedStyle(summary, "::before").display === "none";
  });
  record(`${label}: inline TOC summary has no admonition icon bleed`, tocIconHidden === true);

  // A data table must scroll horizontally, not shrink its columns to fit.
  const tableState = await page.evaluate(() => {
    const wrap = document.querySelector(".md-typeset__scrollwrap");
    const table = wrap ? wrap.querySelector("table:not([class])") : null;
    if (!wrap || !table) return null;
    return {wrapScrollWidth: wrap.scrollWidth, wrapClientWidth: wrap.clientWidth};
  });
  if (tableState) {
    record(`${label}: data table scrolls instead of shrinking to fit`,
      tableState.wrapScrollWidth > tableState.wrapClientWidth + 1,
      `scrollWidth=${tableState.wrapScrollWidth} clientWidth=${tableState.wrapClientWidth}`);
  }

  await context.close();
}

for (const width of [320, 360, 390, 412]) {
  for (const scheme of ["light", "dark"]) {
    const {context, page} = await newPage({width, height: 844}, scheme);
    await gotoPage(page, "/labs/secure-cicd/", scheme);
    const state = await page.evaluate(() => {
      const viewer = document.getElementById("source-secure-cicd");
      const toolbar = viewer.querySelector(".docs-source-viewer__toolbar");
      const actions = [...viewer.querySelectorAll(".docs-source-viewer__button:not([hidden])")];
      const tabs = viewer.querySelector(".docs-source-viewer__tabs");
      const code = viewer.querySelector(".docs-source-viewer__code code");
      const viewerRect = viewer.getBoundingClientRect();
      const toolbarRect = toolbar.getBoundingClientRect();
      return {
        contained: toolbarRect.left >= viewerRect.left - 1 && toolbarRect.right <= viewerRect.right + 1,
        actionHeights: actions.map(button => button.getBoundingClientRect().height),
        tabOverflowContained: tabs.scrollWidth >= tabs.clientWidth && tabs.getBoundingClientRect().right <= viewerRect.right + 1,
        fontSize: parseFloat(getComputedStyle(code).fontSize),
        noDocumentOverflow: document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1
      };
    });
    const label = `source-viewer mobile ${width}px ${scheme}`;
    record(`${label}: toolbar and tab row stay within viewer`, state.contained && state.tabOverflowContained, JSON.stringify(state));
    record(`${label}: visible actions are touch-friendly`, state.actionHeights.length >= 2 && state.actionHeights.every(height => height >= 40), `heights=${state.actionHeights.join(",")}`);
    record(`${label}: code remains readable`, state.fontSize >= 12.5, `fontSize=${state.fontSize}`);
    record(`${label}: no document overflow`, state.noDocumentOverflow);
    await context.close();
  }
}

{
  const {context, page} = await newPage({width: 390, height: 844}, "light");
  await gotoPage(page, "/scripts/cloud-security/", "light");
  const label = "mobile polish source-viewer 390x844";

  // A long source line must be genuinely reachable by scrolling the <pre>, not
  // just ink-overflow past the edge of a <code> box the ancestor never counts.
  const codeState = await page.evaluate(() => {
    const pre = document.querySelector(".docs-source-viewer__code");
    if (!pre) return null;
    const before = pre.scrollLeft;
    pre.scrollLeft = 300;
    const after = pre.scrollLeft;
    pre.scrollLeft = before;
    return {scrollWidth: pre.scrollWidth, clientWidth: pre.clientWidth, movedOnScroll: after > 0};
  });
  record(`${label}: source code <pre> registers real scrollable overflow`,
    codeState && codeState.scrollWidth > codeState.clientWidth + 1,
    codeState ? `scrollWidth=${codeState.scrollWidth} clientWidth=${codeState.clientWidth}` : "no source viewer found");
  record(`${label}: source code <pre> is actually scrollable (not just measured wider)`,
    codeState && codeState.movedOnScroll === true);

  await context.close();
}

{
  const {context, page} = await newPage({width: 390, height: 844}, "light");
  await gotoPage(page, "/docs/certification-notes/az-900/domain-1-concepts/", "light");
  const label = "mobile polish breadcrumbs 390x844";

  // When the breadcrumb trail overflows a narrow viewport, the current page
  // (the last, most useful crumb) must be what's visible by default, not
  // scrolled out of view behind "Home".
  const state = await page.evaluate(() => {
    const el = document.querySelector(".docs-breadcrumbs");
    if (!el) return null;
    return {scrollLeft: el.scrollLeft, scrollWidth: el.scrollWidth, clientWidth: el.clientWidth};
  });
  if (state && state.scrollWidth > state.clientWidth + 1) {
    record(`${label}: overflowing breadcrumbs auto-scroll to reveal the current page`,
      state.scrollLeft >= state.scrollWidth - state.clientWidth - 1,
      `scrollLeft=${state.scrollLeft} scrollWidth=${state.scrollWidth} clientWidth=${state.clientWidth}`);
  } else {
    record(`${label}: breadcrumb trail overflows at this viewport (test is meaningful)`, false,
      state ? `scrollWidth=${state.scrollWidth} clientWidth=${state.clientWidth}` : "no breadcrumbs found");
  }

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
  "/", ARTICLE_URL, "/devsecops/secure-cicd-pipeline-design/", "/research/", "/scripts/", "/scripts/cloud-security/", "/scripts/devsecops/",
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

if (process.env.CAPTURE_UI_SCREENSHOTS === "1") {
  const componentDir = path.join(root, "qa-artifacts", "ui-components");
  fs.mkdirSync(componentDir, {recursive: true});

  const {context, page} = await newPage({width: 1440, height: 900}, "light");
  await gotoPage(page, "/labs/secure-cicd/", "light");
  const viewer = page.locator("#source-secure-cicd");
  await viewer.screenshot({path: path.join(componentDir, "source-short-light.png")});
  await page.locator('#source-secure-cicd-tab-2').click();
  await viewer.screenshot({path: path.join(componentDir, "source-long-collapsed-light.png")});
  await page.locator("#source-secure-cicd [data-expand-source]").click();
  await viewer.screenshot({path: path.join(componentDir, "source-long-expanded-light.png")});
  await page.locator("#source-secure-cicd [data-wrap-source]").click();
  await viewer.screenshot({path: path.join(componentDir, "source-long-wrapped-light.png")});
  await page.locator(".docs-article-header").screenshot({path: path.join(componentDir, "breadcrumbs-light.png")});
  await context.close();

  const dark = await newPage({width: 1440, height: 900}, "dark");
  await gotoPage(dark.page, "/labs/secure-cicd/", "dark");
  await dark.page.locator("#source-secure-cicd").screenshot({path: path.join(componentDir, "source-short-dark.png")});
  await dark.context.close();

  const search = await newPage({width: 1440, height: 900}, "light");
  await gotoPage(search.page, "/", "light");
  const searchInput = search.page.locator('[data-md-component="search-query"]');
  await searchInput.click();
  await searchInput.pressSequentially("secure cicd", {delay: 20});
  await search.page.locator(".md-search-result__article").first().waitFor({state: "visible", timeout: 10000});
  await search.page.waitForFunction(() => Number.parseFloat(getComputedStyle(document.querySelector(".md-search__output")).opacity) >= .999);
  await search.page.locator(".md-search__output").screenshot({path: path.join(componentDir, "search-results-light.png")});
  await search.context.close();

  const mobile = await newPage({width: 390, height: 844}, "dark");
  await gotoPage(mobile.page, "/labs/secure-cicd/", "dark");
  await mobile.page.locator('label.md-header__button[for="__drawer"]').click();
  await mobile.page.waitForFunction(() => {
    const drawer = document.querySelector(".docs-left-nav");
    const rect = drawer?.getBoundingClientRect();
    return Boolean(document.getElementById("__drawer")?.checked && rect && rect.left >= 0);
  });
  await mobile.page.waitForTimeout(250);
  await mobile.page.screenshot({path: path.join(componentDir, "mobile-drawer-dark.png")});
  await mobile.context.close();
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
