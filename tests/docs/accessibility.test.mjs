import fs from "node:fs";
import path from "node:path";
import {createRequire} from "node:module";
import {chromium} from "playwright";
import {lifecycle, serveSite, writeReport} from "./site-helper.mjs";

const require = createRequire(import.meta.url);
const axeSource = fs.readFileSync(require.resolve("axe-core/axe.min.js"), "utf8");
const urls = Object.entries(lifecycle).filter(([, item]) => item.status !== "archived").map(([url]) => url);
if (!urls.includes("/404.html")) urls.push("/404.html");
const viewports = [{name: "desktop", width: 1440, height: 900}, {name: "mobile", width: 390, height: 844}];
const schemes = ["light", "dark"];
const failures = [];
const results = [];
const server = await serveSite();
const browser = await chromium.launch();

async function audit(page, url, state = "default") {
  const response = await page.goto(`${server.base}${url}`, {waitUntil: "load"});
  if (!response || response.status() !== 200) {
    failures.push({url, state, id: "load", detail: `HTTP ${response?.status()}`});
    return;
  }
  await page.addScriptTag({content: axeSource});
  const report = await page.evaluate(async () => window.axe.run(document, {
    resultTypes: ["violations"],
    runOnly: {type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"]},
  }));
  const violations = report.violations.map(item => ({id: item.id, impact: item.impact, help: item.help, targets: item.nodes.slice(0, 4).map(node => node.target.join(" "))}));
  results.push({url, state, violations});
  for (const violation of violations) failures.push({url, state, ...violation});
}

for (const viewport of viewports) {
  for (const scheme of schemes) {
    const context = await browser.newContext({viewport, colorScheme: scheme});
    await context.addInitScript(selected => {
      localStorage.setItem("/.__palette", JSON.stringify({index: selected === "dark" ? 1 : 0}));
    }, scheme);
    const page = await context.newPage();
    for (const url of urls) await audit(page, url, `${viewport.name}-${scheme}`);
    if (viewport.name === "desktop") {
      await page.goto(`${server.base}/appsec/ai-agent-security/`, {waitUntil: "load"});
      await page.locator("[data-docs-focus]").click();
      await page.addScriptTag({content: axeSource});
      await audit(page, "/appsec/ai-agent-security/", `${viewport.name}-${scheme}-focus`);
      await page.goto(`${server.base}/labs/ai-agent-security/`, {waitUntil: "load"});
      const expand = page.locator("[data-expand-source]");
      if (await expand.isVisible()) await expand.click();
      await audit(page, "/labs/ai-agent-security/", `${viewport.name}-${scheme}-source-expanded`);
    }
    console.log(`Accessibility: ${viewport.name}/${scheme} complete.`);
    await context.close();
  }
}

await browser.close();
await server.close();
writeReport("accessibility-report.json", {pages: urls.length, combinations: 4, violationCount: failures.length, failures, results});
if (failures.length) {
  console.error(`Accessibility audit found ${failures.length} violation record(s).`);
  for (const failure of failures.slice(0, 50)) console.error(`- ${failure.url} [${failure.state}] ${failure.id}: ${failure.help || failure.detail} ${(failure.targets || []).join(", ")}`);
  process.exit(1);
}
console.log(`Accessibility audit passed: ${urls.length} routes in desktop/mobile and light/dark, plus interactive states.`);
