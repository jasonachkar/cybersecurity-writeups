"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const ROOT = path.resolve(__dirname, "..");
const targets = ["README.md", "docs/research-audit/content-inventory.md"];
const before = new Map(targets.map((file) => [file, fs.existsSync(path.join(ROOT, file)) ? fs.readFileSync(path.join(ROOT, file), "utf8") : null]));

for (const generator of ["scripts/generate-index.js", "scripts/generate-content-inventory.js"]) {
  const result = spawnSync(process.execPath, [generator], { cwd: ROOT, encoding: "utf8" });
  if (result.status !== 0) {
    process.stderr.write(result.stderr || result.stdout);
    process.exit(result.status || 1);
  }
}

const changed = [];
for (const target of targets) {
  const absolute = path.join(ROOT, target);
  const prior = before.get(target);
  const after = fs.existsSync(absolute) ? fs.readFileSync(absolute, "utf8") : null;
  if (prior !== after) changed.push(target);
  if (prior === null && fs.existsSync(absolute)) fs.rmSync(absolute);
  else if (prior !== null) fs.writeFileSync(absolute, prior, "utf8");
}

if (changed.length) {
  console.error(`Generated content is stale: ${changed.join(", ")}. Run npm run index:generate.`);
  process.exit(1);
}
console.log("Generated README index and content inventory are current.");
