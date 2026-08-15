"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { createResearch, parseArguments } = require("./research-new");

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "research-new-"));
  for (const domain of ["appsec", "cloud-security", "devsecops", "threat-intel"]) fs.mkdirSync(path.join(root, domain));
  fs.writeFileSync(path.join(root, "appsec", "existing.md"), "---\norder: 20\n---\n\n# Existing\n");
  return root;
}

test("validates required arguments, domains, and slugs", () => {
  assert.throws(() => parseArguments([]), /missing required/);
  assert.throws(() => parseArguments(["--domain", "unknown", "--slug", "valid", "--title", "Valid"]), /unsupported domain/);
  assert.throws(() => parseArguments(["--domain", "appsec", "--slug", "Not Valid", "--title", "Valid"]), /kebab-case/);
});

test("creates safe requires-review metadata at the next domain order", () => {
  const root = fixture();
  const result = createResearch(["--domain", "appsec", "--slug", "secure-token-exchange", "--title", "Secure Token Exchange"], root, "2026-08-15");
  assert.equal(result.metadata.order, 30);
  assert.equal(result.metadata.reviewStatus, "requires-review");
  assert.equal(result.metadata.sourceQuality, "requires-review");
  assert.deepEqual(result.metadata.validatedAgainst, []);
  assert.match(fs.readFileSync(result.target, "utf8"), /# Secure Token Exchange/);
  assert.throws(() => createResearch(["--domain", "appsec", "--slug", "secure-token-exchange", "--title", "Secure Token Exchange"], root), /already exists/);
});
