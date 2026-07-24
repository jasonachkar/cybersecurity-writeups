"use strict";

const SITE_URL = (process.env.SITE_URL || "https://docs.jasonachkardiab.com").replace(/\/+$/, "");
const EXPECTED_COMMIT = (
  process.env.SITE_SOURCE_COMMIT ||
  process.env.GITHUB_SHA ||
  ""
).toLowerCase();
const EXPECTED_BRANCH = process.env.SITE_SOURCE_BRANCH || "main";
const EXPECTED_REPOSITORY = "jasonachkar/cybersecurity-writeups";
const EXPECTED_REPOSITORY_URL = `https://github.com/${EXPECTED_REPOSITORY}`;
const ATTEMPTS = Number.parseInt(process.env.DEPLOY_CHECK_ATTEMPTS || "1", 10);
const DELAY_MS = Number.parseInt(process.env.DEPLOY_CHECK_DELAY_MS || "10000", 10);
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const UTC_TIMESTAMP_PATTERN =
  /^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\dZ$/;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function validateInputs() {
  assert(SHA_PATTERN.test(EXPECTED_COMMIT), "SITE_SOURCE_COMMIT or GITHUB_SHA must be a full lowercase Git SHA");
  assert(Number.isInteger(ATTEMPTS) && ATTEMPTS >= 1 && ATTEMPTS <= 30, "DEPLOY_CHECK_ATTEMPTS must be from 1 to 30");
  assert(Number.isInteger(DELAY_MS) && DELAY_MS >= 0 && DELAY_MS <= 60000, "DEPLOY_CHECK_DELAY_MS must be from 0 to 60000");
}

async function get(relativePath, attempt) {
  const separator = relativePath.includes("?") ? "&" : "?";
  const url = `${SITE_URL}/${relativePath}${separator}verify=${encodeURIComponent(EXPECTED_COMMIT)}-${attempt}`;
  const response = await fetch(url, {
    redirect: "follow",
    cache: "no-store",
    signal: AbortSignal.timeout(20000),
    headers: {
      accept: "text/html,application/json;q=0.9,*/*;q=0.1",
      "cache-control": "no-cache",
      pragma: "no-cache",
      "user-agent": "cybersecurity-writeups-deployment-check/1.0",
    },
  });
  assert(response.ok, `${relativePath} returned HTTP ${response.status}`);
  assert(response.url.startsWith(`${SITE_URL}/`), `${relativePath} redirected outside ${SITE_URL}`);
  return response.text();
}

function validateTimestamp(value) {
  if (typeof value !== "string" || !UTC_TIMESTAMP_PATTERN.test(value)) return false;
  const parsed = new Date(value);
  return (
    !Number.isNaN(parsed.valueOf()) &&
    parsed.toISOString().replace(".000Z", "Z") === value &&
    parsed.valueOf() <= Date.now() + 5 * 60 * 1000
  );
}

function requireCanonical(html, expected, label) {
  const match = html.match(/<link\b(?=[^>]*\brel=(?:"canonical"|'canonical'))[^>]*\bhref=(?:"([^"]+)"|'([^']+)')[^>]*>/i);
  assert(match, `${label} is missing a canonical link`);
  assert((match[1] || match[2]) === expected, `${label} canonical does not equal ${expected}`);
}

async function check(attempt) {
  const metadataText = await get("site-meta.json", attempt);
  let metadata;
  try {
    metadata = JSON.parse(metadataText);
  } catch (error) {
    throw new Error(`site-meta.json is invalid JSON: ${error.message}`);
  }
  assert(metadata && !Array.isArray(metadata) && typeof metadata === "object", "site-meta.json must be an object");
  assert(metadata.sourceBranch === EXPECTED_BRANCH, `deployed sourceBranch is ${metadata.sourceBranch}, expected ${EXPECTED_BRANCH}`);
  assert(metadata.sourceCommit === EXPECTED_COMMIT, `deployed sourceCommit is ${metadata.sourceCommit}, expected ${EXPECTED_COMMIT}`);
  assert(metadata.generator === "mkdocs", `deployed generator is ${metadata.generator}, expected mkdocs`);
  assert(metadata.repository === EXPECTED_REPOSITORY, `deployed repository is ${metadata.repository}, expected ${EXPECTED_REPOSITORY}`);
  assert(validateTimestamp(metadata.buildTimestamp), "deployed buildTimestamp is not a valid UTC timestamp");

  const homepage = await get("", attempt);
  requireCanonical(homepage, `${SITE_URL}/`, "homepage");
  assert(homepage.includes(EXPECTED_REPOSITORY_URL), "homepage does not link to the source repository");
  assert(homepage.includes(EXPECTED_COMMIT), "homepage footer does not expose the expected full source commit");
  assert(homepage.includes(metadata.buildTimestamp), "homepage footer timestamp differs from site-meta.json");

  const about = await get("about/site-provenance/", attempt);
  requireCanonical(about, `${SITE_URL}/about/site-provenance/`, "provenance page");
  assert(about.includes(EXPECTED_COMMIT), "provenance page does not expose the expected full source commit");
  assert(about.includes(metadata.buildTimestamp), "provenance page timestamp differs from site-meta.json");
}

async function main() {
  validateInputs();
  let lastError;
  for (let attempt = 1; attempt <= ATTEMPTS; attempt += 1) {
    try {
      await check(attempt);
      console.log(`Public deployment matches ${EXPECTED_BRANCH}@${EXPECTED_COMMIT}.`);
      return;
    } catch (error) {
      lastError = error;
      if (attempt < ATTEMPTS) {
        console.warn(`Deployment check attempt ${attempt}/${ATTEMPTS} failed: ${error.message}`);
        await new Promise((resolve) => setTimeout(resolve, DELAY_MS));
      }
    }
  }
  throw lastError;
}

main().catch((error) => {
  console.error(`Public deployment freshness check failed: ${error.message}`);
  process.exitCode = 1;
});
