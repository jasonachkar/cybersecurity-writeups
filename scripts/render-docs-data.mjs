import fs from "node:fs";
import path from "node:path";
import {createRequire} from "node:module";
import {highlightSource} from "./highlight-source.mjs";

const require = createRequire(import.meta.url);
const {buildCatalog} = require("./docs-catalog-lib.js");
const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const catalog = buildCatalog();

function enrichViewer(item) {
  if (!item.sourceFiles) return;
  item.viewerId = `source-${item.id}`;
  item.sourceFiles = item.sourceFiles.map((file, index) => {
    const source = fs.readFileSync(path.join(root, file.path), "utf8").replace(/\r\n/g, "\n");
    const highlighted = highlightSource(source, file.language, `${item.viewerId}-${index}`);
    return {
      ...file,
      filename: path.posix.basename(file.path),
      lineCount: source.length ? source.replace(/\n$/, "").split("\n").length : 0,
      expandable: source.split("\n").length > 100,
      github: `https://github.com/jasonachkar/cybersecurity-writeups/blob/main/${file.path}`,
      raw: `https://raw.githubusercontent.com/jasonachkar/cybersecurity-writeups/main/${file.path}`,
      highlighted,
    };
  });
}

for (const item of [...catalog.labs, ...catalog.scripts]) enrichViewer(item);
// pageMap was assembled before source highlighting; repoint its entries to the
// enriched canonical objects so templates receive the same data everywhere.
for (const item of catalog.labs) catalog.pageMap[`labs/${item.id}/README.md`] = item;
for (const category of catalog.scriptCategories) {
  catalog.pageMap[`scripts/${category.id}.md`].scripts = catalog.scripts.filter(item => item.category === category.id);
}

if (process.argv.includes("--check")) {
  console.log(`Documentation catalog passed: ${catalog.research.length} research, ${catalog.labs.length} labs, ${catalog.scripts.length} scripts.`);
} else {
  process.stdout.write(JSON.stringify(catalog));
}
