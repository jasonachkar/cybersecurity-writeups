#!/usr/bin/env node
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");
const ARTIFACT_PATH = path.join(
  ROOT,
  "labs",
  "supply-chain",
  "artifact",
  "release.txt",
);
const EXPECTED_SHA256 =
  "096407aa951a20498aabd46de33f6c41f190fc7987d3e01779438afc5c65b1c9";
const EXPECTED_BYTES = Buffer.from("release-artifact-v1\n", "utf8");
const attributes = fs.readFileSync(path.join(ROOT, ".gitattributes"), "utf8");
const artifact = fs.readFileSync(ARTIFACT_PATH);
const actualSha256 = crypto.createHash("sha256").update(artifact).digest("hex");
const errors = [];

if (!attributes
  .split(/\r?\n/)
  .some((line) =>
    line.trim() === "labs/supply-chain/artifact/release.txt -text")) {
  errors.push(
    "The release fixture must be marked -text in .gitattributes so checkout cannot rewrite its bytes.",
  );
}
if (!artifact.equals(EXPECTED_BYTES)) {
  errors.push(
    "The release fixture bytes differ from the canonical LF-terminated byte sequence.",
  );
}
if (actualSha256 !== EXPECTED_SHA256) {
  errors.push(
    `Release fixture SHA-256 ${actualSha256} does not match ${EXPECTED_SHA256}.`,
  );
}

if (errors.length) {
  console.error(`Reproducible-fixture validation failed with ${errors.length} error(s):`);
  for (const error of errors) console.error(`- ${error}`);
  process.exit(1);
}

console.log(
  `PASS: supply-chain release fixture has stable bytes and SHA-256 ${actualSha256}.`,
);
