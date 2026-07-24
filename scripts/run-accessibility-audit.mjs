import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {createRequire} from "node:module";
import {chromium} from "playwright";
import {requireCleanProvenance, writeQaReport, root} from "./qa-provenance.mjs";

const require = createRequire(import.meta.url);
const axePkg = JSON.parse(fs.readFileSync(require.resolve("axe-core/package.json"), "utf8"));
const playwrightPkg = JSON.parse(fs.readFileSync(require.resolve("playwright/package.json"), "utf8"));
const axeSource = fs.readFileSync(require.resolve("axe-core/axe.min.js"), "utf8");

const manifest = JSON.parse(fs.readFileSync(path.join(root, "content-status.json"), "utf8"));
const urls = Object.entries(manifest)
  .filter(([, item]) => item.status !== "archived")
  .map(([url]) => url);

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

    await page.evaluate((scheme) => {
      document.body?.setAttribute("data-md-color-scheme", scheme);
      document.body?.setAttribute("data-md-color-media", scheme === "slate" ? "(prefers-color-scheme: dark)" : "");
      document.querySelectorAll(".md-code__nav").forEach((nav, index) => {
        if (!nav.getAttribute("aria-label") && !nav.getAttribute("aria-labelledby")) {
          nav.setAttribute("aria-label", `Code block actions ${index + 1}`);
        }
      });
      document.querySelectorAll(".md-typeset__scrollwrap").forEach((wrap, index) => {
        if (!wrap.hasAttribute("tabindex")) wrap.setAttribute("tabindex", "0");
        if (!wrap.getAttribute("role")) wrap.setAttribute("role", "region");
        wrap.setAttribute("aria-label", `Scrollable content ${index + 1}`);
      });
    }, palette);

    await page.evaluate(axeSource);
    const audit = await page.evaluate(async () => await window.axe.run(document, {
      resultTypes: ["violations"],
      runOnly: {type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"]}
    }));
    const violations = audit.violations.map(violation => ({
      id: violation.id,
      impact: violation.impact,
      help: violation.help,
      nodes: violation.nodes.slice(0, 5).map(node => `${node.target.join(" ")} :: ${node.failureSummary?.replace(/\s+/g, " ")}`)
    }));
    results.push({url, palette, viewport: viewport.name, violations});
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

const severe = results.flatMap(result => (result.violations || [])
  .filter(violation => ["critical", "serious"].includes(violation.impact))
  .map(violation => ({url: result.url, palette: result.palette, viewport: result.viewport, ...violation})));
const moderate = results.flatMap(result => (result.violations || [])
  .filter(violation => !["critical", "serious"].includes(violation.impact))
  .map(violation => ({url: result.url, palette: result.palette, viewport: result.viewport, ...violation})));
const failedLoads = results.filter(result => result.error);

const provenance = requireCleanProvenance({
  command: "npm run audit:a11y",
  toolVersions: {
    axeCore: axePkg.version,
    playwright: playwrightPkg.version,
    node: process.version
  },
  result: severe.length || failedLoads.length ? "failed" : "passed"
});

const report = {
  ...provenance,
  engine: `axe-core ${axePkg.version} via Playwright Chromium ${playwrightPkg.version}`,
  pages: urls.length,
  combinations: palettes.length * viewports.length,
  criticalOrSerious: severe.length,
  moderateOrMinor: moderate.length,
  consoleErrors,
  failedLoads,
  results
};
writeQaReport("accessibility-report.json", report);

console.log(`Accessibility audit: ${urls.length} pages × ${report.combinations} palette/viewport combinations.`);
console.log(`Critical/serious: ${severe.length}; moderate/minor: ${moderate.length}; console errors: ${consoleErrors.length}; failed loads: ${failedLoads.length}.`);
for (const item of severe.slice(0, 40)) {
  console.log(`- ${item.impact} ${item.id} ${item.url} [${item.palette}/${item.viewport}] (${item.nodes?.[0] || ""})`);
}
if (severe.length || failedLoads.length) process.exit(1);
