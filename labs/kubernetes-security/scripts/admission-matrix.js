#!/usr/bin/env node
"use strict";
// Submit every case in admission-cases/cases.yaml to the API server with
// --dry-run=server in one namespace and record the decision. Nothing is persisted.
// Usage: admission-matrix.js <kube-context> <namespace> <outfile>
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const YAML = require("yaml");

const [context, namespace, outfile] = process.argv.slice(2);
if (!context || !namespace || !outfile) {
  console.error("usage: admission-matrix.js <kube-context> <namespace> <outfile>");
  process.exit(2);
}
const cases = YAML.parseAllDocuments(
  fs.readFileSync(path.join(__dirname, "..", "admission-cases", "cases.yaml"), "utf8"),
).map((doc) => doc.toJSON()).filter(Boolean);

const results = {};
for (const pod of cases) {
  pod.metadata.namespace = namespace;
  const run = spawnSync("kubectl", ["--context", context, "create", "--dry-run=server", "-f", "-", "-o", "name"], {
    input: JSON.stringify(pod),
    encoding: "utf8",
  });
  const text = `${run.stderr || ""}`.trim();
  results[pod.metadata.name] = {
    decision: run.status === 0 ? "allow" : "deny",
    // Keep the first line only: enough to see which plugin spoke, short enough to read.
    message: text.split("\n")[0].replace(/\s+/g, " ").slice(0, 400),
  };
}
fs.writeFileSync(outfile, JSON.stringify({ namespace, results }, null, 2) + "\n");
const counts = Object.values(results).reduce((acc, r) => ({ ...acc, [r.decision]: (acc[r.decision] || 0) + 1 }), {});
console.log(`${namespace}: ${JSON.stringify(counts)}`);
