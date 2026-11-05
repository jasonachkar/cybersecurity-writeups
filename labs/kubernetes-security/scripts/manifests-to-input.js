#!/usr/bin/env node
"use strict";
// Turn YAML manifests (files or directories, multi-document) into the OPA input
// {"objects": [...]} used by policies/rego/workload.rego.
// Usage: manifests-to-input.js <path>...   (prints JSON to stdout)
const fs = require("node:fs");
const path = require("node:path");
const YAML = require("yaml");

function files(target) {
  if (fs.statSync(target).isDirectory()) {
    return fs.readdirSync(target).sort().flatMap((entry) => files(path.join(target, entry)));
  }
  return /\.ya?ml$/.test(target) ? [target] : [];
}

const objects = process.argv.slice(2).flatMap(files).flatMap((file) =>
  YAML.parseAllDocuments(fs.readFileSync(file, "utf8")).map((doc) => doc.toJSON()).filter(Boolean),
);
process.stdout.write(JSON.stringify({ objects }));
