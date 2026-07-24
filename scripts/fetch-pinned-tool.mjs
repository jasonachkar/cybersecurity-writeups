#!/usr/bin/env node
/**
 * Download a URL to a local path and verify its SHA-256 digest.
 *
 * Usage:
 *   node scripts/fetch-pinned-tool.mjs <url> <sha256> <destPath>
 *
 * Also exported as `fetchPinnedTool` for verify suites.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";

/**
 * @param {{url: string, sha256: string, destPath: string, force?: boolean}} options
 * @returns {Promise<string>} absolute destination path
 */
export async function fetchPinnedTool({url, sha256, destPath, force = false}) {
  if (!url || !sha256 || !destPath) {
    throw new Error("fetchPinnedTool requires url, sha256, and destPath");
  }
  const expected = String(sha256).trim().toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(expected)) {
    throw new Error(
      `Invalid SHA-256 for ${url}: expected 64 hex chars. ` +
        `CI/tool-pins.mjs must publish a real digest before fetch.`
    );
  }

  const absolute = path.resolve(destPath);
  fs.mkdirSync(path.dirname(absolute), {recursive: true});

  if (!force && fs.existsSync(absolute)) {
    const existing = crypto.createHash("sha256").update(fs.readFileSync(absolute)).digest("hex");
    if (existing === expected) return absolute;
    fs.unlinkSync(absolute);
  }

  const response = await fetch(url, {
    headers: {"user-agent": "cybersecurity-writeups-fetch-pinned-tool/1.0"},
    redirect: "follow"
  });
  if (!response.ok) {
    throw new Error(`Download failed (${response.status} ${response.statusText}): ${url}`);
  }
  const buffer = Buffer.from(await response.arrayBuffer());
  const actual = crypto.createHash("sha256").update(buffer).digest("hex");
  if (actual !== expected) {
    throw new Error(
      `SHA-256 mismatch for ${url}\n  expected: ${expected}\n  actual:   ${actual}`
    );
  }
  fs.writeFileSync(absolute, buffer);
  return absolute;
}

const isDirectRun = process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isDirectRun) {
  const [url, sha256, destPath] = process.argv.slice(2);
  if (!url || !sha256 || !destPath) {
    console.error("Usage: node scripts/fetch-pinned-tool.mjs <url> <sha256> <destPath>");
    process.exit(2);
  }
  fetchPinnedTool({url, sha256, destPath})
    .then((saved) => {
      console.log(`Fetched and verified ${saved}`);
    })
    .catch((error) => {
      console.error(error.message || error);
      process.exit(1);
    });
}
