import fs from "node:fs";
import path from "node:path";
import {test, expect} from "playwright/test";
import {ARTIFACTS, serveSite} from "./site-helper.mjs";

let server;
test.beforeAll(async () => { server = await serveSite(); });
test.afterAll(async () => { await server.close(); });

const pages = [
  {name: "home", url: "/", viewports: [[390, 844], [1440, 900]]},
  {name: "ai-agent", url: "/appsec/ai-agent-security/", viewports: [[390, 844], [1024, 768], [1440, 900]]},
  {name: "scripts", url: "/scripts/devsecops/", viewports: [[390, 844], [1440, 900]]},
  {name: "lab", url: "/labs/ai-agent-security/", viewports: [[390, 844], [1440, 900]]},
];

async function prepare(page, url, width, height, scheme) {
  await page.setViewportSize({width, height});
  await page.emulateMedia({colorScheme: scheme, reducedMotion: "reduce"});
  await page.route(/^https?:\/(?!\/127\.0\.0\.1)/, route => route.abort());
  await page.goto(`${server.base}${url}`, {waitUntil: "load"});
  await page.evaluate(selected => {
    document.body.setAttribute("data-md-color-scheme", selected === "dark" ? "slate" : "default");
    document.body.setAttribute("data-md-color-media", selected === "dark" ? "(prefers-color-scheme: dark)" : "(prefers-color-scheme: light)");
  }, scheme);
  await page.addStyleTag({content: `
    :root { --md-text-font: Arial, sans-serif; --md-code-font: "Courier New", monospace; }
    *, *::before, *::after { animation: none !important; transition: none !important; caret-color: transparent !important; }
  `});
  await page.evaluate(() => document.fonts.ready);
}

for (const entry of pages) {
  for (const [width, height] of entry.viewports) {
    for (const scheme of ["light", "dark"]) {
      test(`${entry.name} ${width}x${height} ${scheme}`, async ({page}) => {
        await prepare(page, entry.url, width, height, scheme);
        await expect(page).toHaveScreenshot(`${entry.name}-${width}x${height}-${scheme}.png`);
      });
    }
  }
}

const states = [
  {name: "focus", url: "/appsec/ai-agent-security/", width: 1440, height: 900, action: async page => page.locator("[data-docs-focus]").click()},
  {name: "article-scrolled", url: "/appsec/ai-agent-security/", width: 1440, height: 900, action: async page => page.evaluate(() => scrollTo(0, 1800))},
  {name: "mobile-drawer", url: "/appsec/ai-agent-security/", width: 390, height: 844, action: async page => page.locator(".md-header label[for='__drawer']").click()},
  {name: "source-expanded", url: "/labs/ai-agent-security/", width: 1440, height: 900, action: async page => page.locator("[data-expand-source]").click()},
];

for (const state of states) {
  test(`${state.name} state`, async ({page}) => {
    await prepare(page, state.url, state.width, state.height, "light");
    await state.action(page);
    await expect(page).toHaveScreenshot(`${state.name}.png`);
    if (process.env.CAPTURE_REVIEW === "1") {
      const output = path.join(ARTIFACTS, "..", "ui-review", "after", `${state.name}.png`);
      fs.mkdirSync(path.dirname(output), {recursive: true});
      await page.screenshot({path: output, animations: "disabled", caret: "hide"});
    }
  });
}
