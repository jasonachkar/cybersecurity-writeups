"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { ROOT, markdownFiles, relative } = require("./content-lib");
const external = process.argv.includes("--external");
const errors = [];
const externalUrls = new Set();
const ignoredSchemes = /^(?:mailto:|tel:|data:|javascript:)/i;
const nonPublicTestHosts = /^(?:https?:\/\/)?(?:localhost|127\.0\.0\.1|\[::1\])(?::|\/|$)/i;

function stripFenceContent(markdown) {
  return markdown.replace(/```[\s\S]*?```/g, "");
}

const files = markdownFiles();
for (const file of files) {
  const source = stripFenceContent(fs.readFileSync(file, "utf8"));
  const linkPattern = /!?(?:\[[^\]]*\])\(([^)\s]+)(?:\s+["'][^"']*["'])?\)/g;
  let match;
  while ((match = linkPattern.exec(source))) {
    const target = match[1].replace(/^<|>$/g, "");
    if (!target || target.startsWith("#") || ignoredSchemes.test(target)) continue;
    if (/^https?:\/\//i.test(target)) {
      if (nonPublicTestHosts.test(target)) continue;
      if (external) externalUrls.add(target);
      continue;
    }
    const withoutQuery = target.split(/[?#]/)[0];
    let decoded;
    try {
      decoded = decodeURIComponent(withoutQuery);
    } catch {
      errors.push(`${relative(file)}: invalid URL encoding in ${target}`);
      continue;
    }
    const resolved = path.resolve(path.dirname(file), decoded.replace(/\//g, path.sep));
    const insideRoot = resolved === ROOT || resolved.startsWith(`${ROOT}${path.sep}`);
    if (!insideRoot) errors.push(`${relative(file)}: relative link escapes repository: ${target}`);
    else if (!fs.existsSync(resolved)) errors.push(`${relative(file)}: missing relative target: ${target}`);
  }
}

async function checkExternal() {
  const failures = [];
  const inaccessible = [];
  const urls = [...externalUrls];
  const accessRestricted = new Set([401, 403, 406, 429]);
  let next = 0;
  async function worker() {
    while (next < urls.length) {
      const url = urls[next++];
      try {
        const response = await fetch(url, {
          method: "GET",
          redirect: "follow",
          signal: AbortSignal.timeout(20_000),
          headers: { "user-agent": "cybersecurity-writeups-link-check/1.0" },
        });
        if (accessRestricted.has(response.status)) inaccessible.push(`${url} returned ${response.status}`);
        else if (response.status >= 400) failures.push(`${url} returned ${response.status}`);
        if (response.redirected && response.url === url) failures.push(`${url} produced a redirect loop`);
      } catch (error) {
        failures.push(`${url}: ${error.message}`);
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(8, urls.length || 1) }, worker));
  errors.push(...failures);
  console.log(`Checked ${urls.length} external URL(s); ${inaccessible.length} authenticated/rate-limited/crawler-restricted response(s) were reported as unverified, not broken.`);
  for (const item of inaccessible) console.warn(`External verification limitation: ${item}`);
}

(async () => {
  if (external) await checkExternal();
  if (errors.length) {
    console.error(`Link validation failed with ${errors.length} error(s):`);
    for (const item of errors) console.error(`- ${item}`);
    process.exit(1);
  }
  console.log(`Link validation passed for ${files.length} Markdown file(s)${external ? " including externally reachable URLs" : " (repository targets)"}.`);
})();
