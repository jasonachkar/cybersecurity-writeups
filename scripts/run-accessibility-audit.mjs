import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import {createRequire} from "node:module";
import {chromium} from "playwright";
import {buildProvenance, writeQaReport, root} from "./qa-provenance.mjs";

const require = createRequire(import.meta.url);
const axePkg = JSON.parse(fs.readFileSync(require.resolve("axe-core/package.json"), "utf8"));
const playwrightPkg = JSON.parse(fs.readFileSync(require.resolve("playwright/package.json"), "utf8"));
const axeSource = fs.readFileSync(require.resolve("axe-core/axe.min.js"), "utf8");

const manifest = JSON.parse(fs.readFileSync(path.join(root, "content-status.json"), "utf8"));
const urls = Object.entries(manifest)
  .filter(([, item]) => item.status !== "archived")
  .map(([url]) => url);

// Always cover the 404 utility page even if classified separately.
if (fs.existsSync(path.join(root, "404.html")) && !urls.includes("/404.html")) {
  urls.push("/404.html");
}

const palettes = ["default", "slate"];
const viewports = [
  {name: "desktop", width: 1280, height: 800},
  {name: "mobile", width: 390, height: 844}
];

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

const browser = await chromium.launch();
const results = [];
const consoleErrors = [];
const helperFailures = [];

async function assertShippedHelper(page, url, palette, viewportName) {
  const check = await page.evaluate(async () => {
    // Wait briefly for deferred portfolio-a11y.js (MutationObserver + rAF).
    const deadline = Date.now() + 2000;
    while (Date.now() < deadline) {
      const navs = [...document.querySelectorAll(".md-code__nav")];
      const wraps = [...document.querySelectorAll(".md-typeset__scrollwrap")];
      const navOk = navs.every(
        (nav) => nav.getAttribute("aria-label") || nav.getAttribute("aria-labelledby")
      );
      const wrapOk = wraps.every(
        (wrap) =>
          wrap.getAttribute("tabindex") === "0" &&
          wrap.getAttribute("role") === "region" &&
          (wrap.getAttribute("aria-label") || wrap.getAttribute("aria-labelledby"))
      );
      if (navOk && wrapOk) {
        return {ok: true, navCount: navs.length, wrapCount: wraps.length};
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    const navs = [...document.querySelectorAll(".md-code__nav")];
    const wraps = [...document.querySelectorAll(".md-typeset__scrollwrap")];
    return {
      ok: false,
      navCount: navs.length,
      wrapCount: wraps.length,
      missingNav: navs
        .filter((nav) => !nav.getAttribute("aria-label") && !nav.getAttribute("aria-labelledby"))
        .length,
      missingWrap: wraps.filter(
        (wrap) =>
          wrap.getAttribute("tabindex") !== "0" ||
          wrap.getAttribute("role") !== "region" ||
          !(wrap.getAttribute("aria-label") || wrap.getAttribute("aria-labelledby"))
      ).length
    };
  });

  if (!check.ok) {
    helperFailures.push({
      url,
      palette,
      viewport: viewportName,
      ...check
    });
  }
  return check.ok;
}

async function auditCombination(palette, viewport) {
  const context = await browser.newContext({
    viewport: {width: viewport.width, height: viewport.height},
    colorScheme: palette === "slate" ? "dark" : "light"
  });
  await context.addInitScript((scheme) => {
    window.localStorage.setItem("/.__palette", JSON.stringify({index: scheme === "slate" ? 1 : 0}));
  }, palette);

  const page = await context.newPage();
  page.on("console", message => {
    if (message.type() === "error") {
      consoleErrors.push({page: page.url(), palette, viewport: viewport.name, text: message.text()});
    }
  });
  page.on("pageerror", error => {
    consoleErrors.push({page: page.url(), palette, viewport: viewport.name, text: String(error)});
  });

  for (const url of urls) {
    const response = await page.goto(`http://127.0.0.1:${port}${url}`, {waitUntil: "load"});
    if (!response || response.status() !== 200) {
      results.push({
        url,
        palette,
        viewport: viewport.name,
        error: `HTTP ${response ? response.status() : "no response"}`
      });
      continue;
    }

    // Apply palette attributes only (no accessibility attribute mutation).
    await page.evaluate((scheme) => {
      document.body?.setAttribute("data-md-color-scheme", scheme);
      document.body?.setAttribute(
        "data-md-color-media",
        scheme === "slate" ? "(prefers-color-scheme: dark)" : ""
      );
    }, palette);

    const helperOk = await assertShippedHelper(page, url, palette, viewport.name);
    if (!helperOk) {
      results.push({
        url,
        palette,
        viewport: viewport.name,
        error: "shipped portfolio-a11y.js attributes missing",
        violations: []
      });
      continue;
    }

    await page.evaluate(axeSource);
    const runAxe = async () => await page.evaluate(async () => await window.axe.run(document, {
      resultTypes: ["violations"],
      runOnly: {type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"]}
    }));
    const audit = await runAxe();
    const violations = audit.violations.map(violation => ({
      id: violation.id,
      impact: violation.impact,
      help: violation.help,
      nodes: violation.nodes.slice(0, 5).map(node => `${node.target.join(" ")} :: ${node.failureSummary?.replace(/\s+/g, " ")}`)
    }));
    results.push({url, palette, viewport: viewport.name, violations});

    // Exercise the enhanced viewer state as well: a secondary/long tab, wrapped
    // lines, and expanded source must remain accessible in both palettes/sizes.
    const hasViewer = await page.locator("[data-source-viewer]").count();
    if (hasViewer) {
      await page.evaluate(() => {
        const viewer = document.querySelector("[data-source-viewer]");
        const tabs = viewer.querySelectorAll("[data-source-tab]");
        if (tabs.length > 1) tabs[tabs.length - 1].click();
        viewer.querySelector("[data-wrap-source]")?.click();
        const expand = viewer.querySelector("[data-expand-source]:not([hidden])");
        if (expand) expand.click();
      });
      const interactiveAudit = await runAxe();
      results.push({
        url: `${url}#source-interactive-state`,
        palette,
        viewport: viewport.name,
        violations: interactiveAudit.violations.map(violation => ({
          id: violation.id,
          impact: violation.impact,
          help: violation.help,
          nodes: violation.nodes.slice(0, 5).map(node => `${node.target.join(" ")} :: ${node.failureSummary?.replace(/\s+/g, " ")}`)
        }))
      });
    }
  }

  await context.close();
}

for (const palette of palettes) {
  for (const viewport of viewports) {
    await auditCombination(palette, viewport);
  }
}

await browser.close();
server.close();

const allViolations = results.flatMap(result => (result.violations || [])
  .map(violation => ({url: result.url, palette: result.palette, viewport: result.viewport, ...violation})));
const failedLoads = results.filter(result => result.error);
const failed =
  allViolations.length > 0 ||
  failedLoads.length > 0 ||
  consoleErrors.length > 0 ||
  helperFailures.length > 0;

const provenance = buildProvenance({
  command: "npm run verify:a11y",
  toolVersions: {
    axeCore: axePkg.version,
    playwright: playwrightPkg.version,
    node: process.version
  },
  result: failed ? "failed" : "passed"
});

const report = {
  ...provenance,
  engine: `axe-core ${axePkg.version} via Playwright Chromium ${playwrightPkg.version}`,
  pages: urls.length,
  combinations: palettes.length * viewports.length,
  violationCount: allViolations.length,
  criticalOrSerious: allViolations.filter(v => ["critical", "serious"].includes(v.impact)).length,
  moderateOrMinor: allViolations.filter(v => !["critical", "serious"].includes(v.impact)).length,
  consoleErrors,
  helperFailures,
  failedLoads,
  results,
  note: "Audit tests the shipped DOM after portfolio-a11y.js; the audit itself does not repair accessibility attributes."
};
writeQaReport("accessibility-report.json", report);

console.log(`Accessibility audit: ${urls.length} pages × ${report.combinations} palette/viewport combinations.`);
console.log(`Violations: ${allViolations.length}; console errors: ${consoleErrors.length}; helper failures: ${helperFailures.length}; failed loads: ${failedLoads.length}.`);
for (const item of allViolations.slice(0, 40)) {
  console.log(`- ${item.impact} ${item.id} ${item.url} [${item.palette}/${item.viewport}] (${item.nodes?.[0] || ""})`);
}
if (failed) process.exit(1);
