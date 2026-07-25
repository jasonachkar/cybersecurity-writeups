// Scans public HTML for the marketing/audit-portal wording this site explicitly
// rejects: self-promotional "production-grade" style claims, and labels left
// over from the old Evidence-registry information architecture. Deliberately
// narrow — it must not flag legitimate technical uses of "production" (e.g.
// "production environment", "production deployment") inside real prose, code,
// or standards references.
import fs from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SKIP_DIR_NAMES = new Set([".git", "node_modules", "qa", "qa-artifacts", ".tools", ".venv", ".idea", "mkdocs-project"]);

function htmlFiles(directory = root) {
  const files = [];
  for (const item of fs.readdirSync(directory, {withFileTypes: true})) {
    if (SKIP_DIR_NAMES.has(item.name)) continue;
    const full = path.join(directory, item.name);
    if (item.isDirectory()) {
      files.push(...htmlFiles(full));
      continue;
    }
    if (item.isFile() && item.name.endsWith(".html")) files.push(full);
  }
  return files;
}

// Marketing/self-promotional phrases banned everywhere in public content.
const MARKETING_PATTERNS = [
  "production-ready", "production ready",
  "production-grade", "production grade",
  "production clean", "production hardened", "hardened for production",
  "production-quality", "production quality",
  "enterprise-grade", "enterprise grade",
  "enterprise-ready", "enterprise ready",
  "battle-tested", "battle tested",
  "real-world ready",
  "professional-grade", "professional grade",
  "senior-level", "senior level",
  "world-class",
  "best-in-class",
  "state-of-the-art",
  "fully hardened",
  "comprehensive solution",
  "complete solution",
  "robust solution",
  "polished solution",
  "industry-leading", "industry leading",
  "turnkey",
  "mission-critical quality",
  "mature solution",
  "deployable at scale",
  "portfolio-grade", "portfolio grade",
  "recruiter-ready", "recruiter ready",
  "this proves senior-level expertise",
  "this demonstrates enterprise security maturity",
  "this showcases production engineering",
  "this demonstrates professional excellence"
].map(phrase => phrase.toLowerCase());

// Labels/copy from the old Evidence-registry / audit-portal information
// architecture. If any of these resurface, something regressed back toward
// the removed IA rather than the current Research/Labs/Scripts/About one.
const STALE_LABEL_PATTERNS = [
  "evidence registry",
  "quality methodology",
  "site provenance",
  "evidence-first security engineering",
  "inspect the evidence registry",
  "review engineering work",
  "security engineering decisions you can audit",
  "publication details",
  "publication target",
  "publication review",
  "reviewed branch",
  "pr #5",
  "codex/validated-gh-pages-deployment"
].map(phrase => phrase.toLowerCase());

function stripTags(html) {
  return html
    .replace(/<script\b[\s\S]*?<\/script>/gi, " ")
    .replace(/<style\b[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&(?:amp|lt|gt|quot|#39|apos|nbsp);/g, " ")
    .toLowerCase();
}

const failures = [];
const files = htmlFiles();
for (const file of files) {
  const raw = fs.readFileSync(file, "utf8");
  const text = stripTags(raw);
  const relative = path.relative(root, file).split(path.sep).join("/");
  for (const phrase of MARKETING_PATTERNS) {
    if (text.includes(phrase)) failures.push(`${relative}: marketing phrase "${phrase}"`);
  }
  for (const phrase of STALE_LABEL_PATTERNS) {
    if (text.includes(phrase)) failures.push(`${relative}: stale Evidence-era label "${phrase}"`);
  }
}

if (failures.length) {
  console.error(`Editorial style check failed (${failures.length}):`);
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(`Editorial style check passed across ${files.length} public HTML pages (${MARKETING_PATTERNS.length} marketing patterns, ${STALE_LABEL_PATTERNS.length} stale-label patterns).`);
