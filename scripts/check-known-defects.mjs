import fs from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const SKIP_DIR_NAMES = new Set([".git", "node_modules", "qa"]);
const PUBLIC_CONTENT = /\.(?:html|json|css|ya?ml)$/i;
const EXECUTABLE = /\.(?:go|js|mjs|ts|tf|rego|sql|bicep|ps1|sh|md)$/i;
const EXECUTABLE_ROOTS = [
  "labs",
  "appsec/scripts",
  "cloud-security/scripts",
  "devsecops/scripts",
  "threat-intel/scripts",
  ".github/workflows"
];

function isUnderExecutableRoot(relativePath) {
  const normalized = relativePath.split(path.sep).join("/");
  return EXECUTABLE_ROOTS.some(
    (prefix) => normalized === prefix || normalized.startsWith(`${prefix}/`)
  );
}

function filesBelow(directory = root) {
  const files = [];
  for (const item of fs.readdirSync(directory, {withFileTypes: true})) {
    if (SKIP_DIR_NAMES.has(item.name)) continue;
    const full = path.join(directory, item.name);
    if (item.isDirectory()) {
      files.push(...filesBelow(full));
      continue;
    }
    if (!item.isFile()) continue;
    const relative = path.relative(root, full);
    if (PUBLIC_CONTENT.test(item.name)) {
      files.push(full);
      continue;
    }
    if (EXECUTABLE.test(item.name) && isUnderExecutableRoot(relative)) {
      files.push(full);
    }
  }
  return files;
}

const checks = [
  ["Sentinel user-agent JSON parse", /parse_json\(RequestParameters\)\.userAgent/g],
  ["invalid API Gateway VPC Link to Lambda", /API Gateway\s*(?:→|&rarr;|->)\s*Private VPC Link\s*(?:→|&rarr;|->)\s*AWS Lambda/gi],
  ["API keys described as validators", /API Key validators/g],
  ["Secret exposure attributed to pod describe", /kubectl describe pod/g],
  ["namespaced policy emitted as cluster TracingPolicy", /kind:\s*TracingPolicy\s*[\r\n]+metadata:\s*[\r\n]+\s*namespace:\s*prod/g],
  ["Linux namespace selector misused for Kubernetes namespace", /matchNamespaces:\s*[\r\n]+\s*-\s*["']?prod["']?/g],
  ["absolute per-function IAM-role requirement", /Every function must have its own dedicated IAM role/gi],
  ["universal WAF requirement", /Always configure a WAF/gi],
  ["absolute static-credential claim", /static credentials are fundamentally insecure/gi],
  ["unsupported RASP evasion rating", /RASP evasion vulnerability:\s*Low/gi],
  ["S3 universally called an interface endpoint", /S3\s+(?:is|—|-)\s+(?:an?\s+)?interface endpoint/gi],
  ["stale source branch", /codex\/production-security-content-verification/g],
  ["incorrect author name", /Jason Achkardiab/g],
  ["stale embedded source SHA", /55312d775b5fd520a07b2797eb6163501120aab8/g],
  ["remote Font Awesome dependency", /font-awesome|cdnjs\.cloudflare\.com\/ajax\/libs\/font-awesome/gi],
  ["remote Google font dependency", /fonts\.(?:googleapis|gstatic)\.com/gi],
  ["remote JavaScript dependency", /<script\b[^>]*src=["']https?:\/\//gi],
  ["wildcard RDP default in Terraform", /allowed_rdp_source_ip\s*=\s*"\*"/gi],
  ["pull_request_target with untrusted checkout", /pull_request_target[\s\S]{0,400}ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)\s*\}\}/gi],
  ["token printed to logs", /console\.(?:log|info|debug|error)\([^\)]*(?:token|secret|password|api[_-]?key)/gi],
  ["manually trusted JWT key URL from token input", /jwks(?:Uri|URL)\s*[:=]\s*[^\n]*(?:header|payload|token)/gi]
];

const failures = [];
const files = filesBelow();
for (const file of files) {
  const text = fs.readFileSync(file, "utf8");
  for (const [label, regex] of checks) {
    regex.lastIndex = 0;
    if (regex.test(text)) failures.push(`${path.relative(root, file)}: ${label}`);
  }
}

if (failures.length) {
  console.error(`Known-defect check failed (${failures.length}):`);
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(`Known-defect check passed across ${files.length} public/executable artifacts (${checks.length} deterministic patterns).`);
console.log("Note: string absence is not semantic proof; compilers, tests, and native policy tooling remain authoritative.");
