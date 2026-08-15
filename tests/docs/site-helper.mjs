import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import {fileURLToPath} from "node:url";

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
export const SITE = path.join(ROOT, ".artifacts", "site");
export const ARTIFACTS = path.join(ROOT, ".artifacts", "qa");
export const lifecycle = JSON.parse(fs.readFileSync(path.join(ROOT, "publishing/content-status.json"), "utf8"));
export const indexableUrls = Object.entries(lifecycle).filter(([, item]) => item.indexable === true && item.status !== "archived").map(([url]) => url);

export function outputForUrl(url) {
  if (url === "/") return "index.html";
  if (path.posix.extname(url)) return url.replace(/^\//, "");
  return `${url.replace(/^\//, "")}index.html`;
}

export function readPage(url) {
  return fs.readFileSync(path.join(SITE, outputForUrl(url)), "utf8");
}

const contentTypes = {".html": "text/html", ".css": "text/css", ".js": "text/javascript", ".json": "application/json", ".svg": "image/svg+xml", ".xml": "application/xml"};

export async function serveSite() {
  const server = http.createServer((request, response) => {
    const clean = decodeURIComponent(request.url.split(/[?#]/)[0]);
    const relative = outputForUrl(clean);
    const target = path.resolve(SITE, relative);
    if (!target.startsWith(`${SITE}${path.sep}`) || !fs.existsSync(target) || !fs.statSync(target).isFile()) {
      response.writeHead(404).end("not found");
      return;
    }
    response.writeHead(200, {"content-type": `${contentTypes[path.extname(target)] || "application/octet-stream"}; charset=utf-8`});
    response.end(fs.readFileSync(target));
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  return {base: `http://127.0.0.1:${server.address().port}`, close: () => new Promise(resolve => server.close(resolve))};
}

export function writeReport(name, payload) {
  fs.mkdirSync(ARTIFACTS, {recursive: true});
  fs.writeFileSync(path.join(ARTIFACTS, name), `${JSON.stringify(payload, null, 2)}\n`);
}
