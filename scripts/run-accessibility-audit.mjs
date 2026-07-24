import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {createRequire} from "node:module";
import {chromium} from "playwright";
import {REVIEW_TIMESTAMP} from "./site-config.mjs";

const require = createRequire(import.meta.url);
const axeSource = fs.readFileSync(require.resolve("axe-core/axe.min.js"), "utf8");
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const manifest = JSON.parse(fs.readFileSync(path.join(root, "content-status.json"), "utf8"));
const urls = Object.entries(manifest)
  .filter(([, item]) => item.status !== "archived")
  .map(([url]) => url);

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
    if (process.env.LOG_404) console.log("404:", request.url);
    response.writeHead(404);
    response.end("not found");
    return;
  }
  response.writeHead(200, {"content-type": types[path.extname(target).toLowerCase()] || "application/octet-stream"});
  response.end(fs.readFileSync(target));
});
await new Promise(resolve => server.listen(8080, "127.0.0.1", resolve));

const browser = await chromium.launch();
const page = await browser.newPage();
const results = [];
const consoleErrors = [];
page.on("console", message => {
  if (message.type() === "error") consoleErrors.push({page: page.url(), text: message.text()});
});
page.on("pageerror", error => consoleErrors.push({page: page.url(), text: String(error)}));

for (const url of urls) {
  const response = await page.goto(`http://127.0.0.1:8080${url}`, {waitUntil: "load"});
  if (!response || response.status() !== 200) {
    results.push({url, error: `HTTP ${response ? response.status() : "no response"}`});
    continue;
  }
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
  results.push({url, violations});
}

await browser.close();
server.close();

const severe = results.flatMap(result => (result.violations || [])
  .filter(violation => ["critical", "serious"].includes(violation.impact))
  .map(violation => ({url: result.url, ...violation})));
const moderate = results.flatMap(result => (result.violations || [])
  .filter(violation => !["critical", "serious"].includes(violation.impact))
  .map(violation => ({url: result.url, ...violation})));
const failedLoads = results.filter(result => result.error);

const report = {
  timestamp: REVIEW_TIMESTAMP,
  engine: `axe-core ${JSON.parse(fs.readFileSync(require.resolve("axe-core/package.json"), "utf8")).version} via Playwright Chromium`,
  pages: urls.length,
  criticalOrSerious: severe.length,
  moderateOrMinor: moderate.length,
  consoleErrors,
  failedLoads,
  results
};
fs.mkdirSync(path.join(root, "qa"), {recursive: true});
fs.writeFileSync(path.join(root, "qa/accessibility-report.json"), `${JSON.stringify(report, null, 2)}\n`);

console.log(`Accessibility audit: ${urls.length} indexable pages with ${report.engine}.`);
console.log(`Critical/serious violations: ${severe.length}; moderate/minor: ${moderate.length}; console errors: ${consoleErrors.length}; failed loads: ${failedLoads.length}.`);
for (const item of severe.slice(0, 30)) console.log(`- ${item.impact} ${item.id} ${item.url} (${item.nodes[0] || ""})`);
if (severe.length || failedLoads.length) process.exit(1);
