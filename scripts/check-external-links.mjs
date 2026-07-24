import fs from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {REVIEW_TIMESTAMP, SITE_ORIGIN} from "./site-config.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(fs.readFileSync(path.join(root, "content-status.json"), "utf8"));
const urls = new Set();

for (const [publicUrl, status] of Object.entries(manifest)) {
  if (status.status === "archived") continue;
  const file = publicUrl === "/" ? "index.html" : publicUrl === "/404.html" ? "404.html" : `${publicUrl.slice(1)}index.html`;
  const html = fs.readFileSync(path.join(root, file), "utf8");
  for (const match of html.matchAll(/<a\b[^>]*href=["'](https?:\/\/[^"'#]+(?:#[^"']*)?)["']/gi)) {
    const url = new URL(match[1]);
    url.hash = "";
    if (url.origin !== SITE_ORIGIN) urls.add(url.href);
  }
}

async function probe(url) {
  // Some standards hosts (rfc-editor.org, csrc.nist.gov) answer non-browser
  // user agents with 404, so a browser-like UA avoids false brokens.
  const headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"};
  for (const method of ["HEAD", "GET"]) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);
    try {
      const response = await fetch(url, {method, headers, redirect: "follow", signal: controller.signal});
      clearTimeout(timeout);
      if (response.ok || (response.status >= 300 && response.status < 400)) return {url, result: "reachable", status: response.status, finalUrl: response.url};
      // rfc-editor.org answers HEAD with 404 for pages that return 200 to GET,
      // so every non-success HEAD result must be confirmed with a GET.
      if (method === "HEAD") continue;
      if ([404, 410].includes(response.status)) return {url, result: "broken", status: response.status, finalUrl: response.url};
      return {url, result: "limited", status: response.status, finalUrl: response.url};
    } catch (error) {
      clearTimeout(timeout);
      if (method === "GET") return {url, result: "limited", error: error.name === "AbortError" ? "timeout" : error.message};
    }
  }
  return {url, result: "limited", error: "unavailable"};
}

const queue = [...urls].sort();
const results = new Array(queue.length);
let cursor = 0;
async function worker() {
  while (cursor < queue.length) {
    const index = cursor++;
    results[index] = await probe(queue[index]);
  }
}
await Promise.all(Array.from({length: Math.min(8, queue.length)}, () => worker()));

const counts = results.reduce((acc, item) => ({...acc, [item.result]: (acc[item.result] || 0) + 1}), {});
const report = {timestamp: REVIEW_TIMESTAMP, checked: results.length, counts, results};
fs.mkdirSync(path.join(root, "qa"), {recursive: true});
fs.writeFileSync(path.join(root, "qa/external-link-report.json"), `${JSON.stringify(report, null, 2)}\n`);

console.log(`External-link check: ${results.length} unique links; ${counts.reachable || 0} reachable, ${counts.limited || 0} rate-limited/authenticated/unavailable, ${counts.broken || 0} definite 404/410.`);
for (const item of results.filter(result => result.result !== "reachable")) console.log(`- ${item.result}: ${item.url} (${item.status || item.error})`);
if (counts.broken) process.exit(1);
