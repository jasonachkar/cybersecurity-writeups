"use strict";

const fs = require("node:fs");
const { allRepositoryFiles, relative } = require("./content-lib");
const errors = [];
const files = allRepositoryFiles((file) => /\.ya?ml$/i.test(file));

for (const file of files) {
  const lines = fs.readFileSync(file, "utf8").split(/\r?\n/);
  lines.forEach((line, index) => {
    const match = line.match(/^\s*-?\s*uses:\s*["']?([^\s"']+)/);
    if (!match) return;
    const value = match[1];
    if (value.startsWith("./") || value.startsWith("docker://") && /@sha256:[a-f0-9]{64}$/i.test(value)) return;
    if (!/@[a-f0-9]{40}$/i.test(value)) {
      errors.push(`${relative(file)}:${index + 1}: action must use a full 40-character commit SHA: ${value}`);
    }
  });
}

if (errors.length) {
  console.error(`Action pin validation failed with ${errors.length} error(s):`);
  for (const item of errors) console.error(`- ${item}`);
  process.exit(1);
}
console.log(`Action pin validation passed across ${files.length} YAML file(s).`);
