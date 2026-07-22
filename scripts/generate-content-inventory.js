#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");
const OUTPUT = path.join(ROOT, "docs", "research-audit", "content-inventory.md");
const CONTENT_ROOTS = ["appsec", "cloud-security", "devsecops", "threat-intel", "docs"];
const EXCLUDED_PREFIXES = [
  "docs/research-audit/",
  "docs/standards/",
  "docs/templates/",
];
const FLAGSHIPS = new Set([
  "appsec/saas-multitenancy-isolation.md",
  "devsecops/secure-cicd-pipeline-design.md",
  "devsecops/supply-chain-sbom-signing.md",
  "docs/tutorials/azure-landing-zone/README.md",
]);
const MANUAL_ACTIONS = new Map([
  ["appsec/oauth2-oidc-deep-dive.md", "Urgent: validate token audiences, PKCE, sender constraints, and references against final RFCs."],
  ["appsec/saas-multitenancy-isolation.md", "Flagship: keep RLS transaction context, bypass-role controls, and negative tests synchronized with the lab."],
  ["cloud-security/iam-at-scale.md", "Urgent: review federation trust, PassRole, workload identity, and elimination of long-lived keys."],
  ["cloud-security/kubernetes-multi-tenancy.md", "Urgent: preserve precise control-plane, network, kernel, node, and cloud-identity boundaries."],
  ["devsecops/iac-security-and-policy-as-code.md", "Urgent: keep Terraform state locking and drift-response behavior current."],
  ["devsecops/secure-cicd-pipeline-design.md", "Flagship: maintain untrusted-input boundaries, immutable pins, fail semantics, and runnable gate tests."],
  ["devsecops/supply-chain-sbom-signing.md", "Flagship: keep SLSA/SBOM versions and digest/identity/issuer verification policy current."],
  ["docs/tutorials/azure-landing-zone/README.md", "Flagship: review Azure landing-zone design, OIDC identity, policy rollout, and lab compilation."],
  ["threat-intel/cloud-breach-case-studies.md", "Urgent: maintain primary-source incident chronology and label retrospective controls."],
]);

function walk(directory) {
  if (!fs.existsSync(directory)) return [];
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...walk(absolute));
    else if (entry.name.endsWith(".md")) files.push(absolute);
  }
  return files;
}

function parseScalar(value) {
  const trimmed = value.trim();
  if (/^\[.*\]$/.test(trimmed)) {
    return trimmed.slice(1, -1).split(",").map((item) => item.trim().replace(/^['"]|['"]$/g, "")).filter(Boolean);
  }
  if (/^\d+$/.test(trimmed)) return Number(trimmed);
  return trimmed.replace(/^['"]|['"]$/g, "");
}

function parseFrontMatter(content) {
  const match = content.match(/^---\s*\r?\n([\s\S]*?)\r?\n---\s*\r?\n/);
  if (!match) return {};
  const metadata = {};
  let listKey = null;
  for (const line of match[1].split(/\r?\n/)) {
    const list = line.match(/^\s+-\s+(.+)$/);
    if (list && listKey) {
      if (!Array.isArray(metadata[listKey])) metadata[listKey] = [];
      metadata[listKey].push(parseScalar(list[1]));
      continue;
    }
    const keyValue = line.match(/^([A-Za-z][A-Za-z0-9]*):\s*(.*)$/);
    if (!keyValue) continue;
    listKey = keyValue[1];
    metadata[listKey] = keyValue[2] ? parseScalar(keyValue[2]) : [];
  }
  return metadata;
}

function firstHeading(content, fallback) {
  const match = content.match(/^#\s+(.+)$/m);
  return match ? match[1].replace(/[*_`]/g, "").trim() : fallback;
}

function words(content) {
  return content
    .replace(/^---[\s\S]*?---\s*/m, "")
    .replace(/```[\s\S]*?```/g, "")
    .replace(/<[^>]+>/g, " ")
    .split(/\s+/)
    .filter(Boolean).length;
}

function linkCount(content) {
  return (content.match(/https:\/\//g) || []).length;
}

function codeLanguages(content) {
  return [...content.matchAll(/^```([^\s`]*)/gm)].map((match) => match[1] || "unlabeled");
}

function topicFor(content, relative) {
  const haystack = `${relative} ${content}`.toLowerCase();
  const candidates = [
    ["Software supply chain", /supply.chain|sbom|slsa|sigstore|cosign/],
    ["CI/CD", /ci\/cd|pipeline|github actions|azure devops/],
    ["Azure", /azure|entra/],
    ["AWS", /\baws\b|amazon web services|\biam\b/],
    ["Kubernetes", /kubernetes|\bk8s\b|kubectl/],
    ["OAuth/OIDC", /oauth|oidc|openid/],
    ["PostgreSQL", /postgres|row.level security|\brls\b/],
    ["Application security", /appsec|application security|owasp/],
    ["Threat intelligence", /threat intel|incident|breach|mitre att&ck/],
    ["Cryptography", /cryptograph|encryption|post.quantum|\bpqc\b/],
    ["Cloud security", /cloud security|landing zone|multi.cloud/],
  ];
  const matches = candidates.filter(([, pattern]) => pattern.test(haystack)).map(([name]) => name);
  return { primary: matches[0] || "General security", secondary: matches.slice(1, 4) };
}

function versions(content) {
  const matches = content.match(/\b(?:v?\d+\.\d+(?:\.\d+)?|RFC\s*\d{4}|SP\s*800-\d+[A-Za-z]?|FIPS\s*\d{3})\b/gi) || [];
  return [...new Set(matches.map((item) => item.trim()))].slice(0, 7);
}

function standards(content) {
  const names = ["OWASP", "ASVS", "OAuth", "OpenID Connect", "NIST SSDF", "NIST", "SLSA", "CycloneDX", "SPDX", "MITRE ATT&CK", "MITRE ATLAS", "CISA KEV", "CIS", "ISO 27001"];
  return names.filter((name) => new RegExp(name.replace(" ", "\\s*"), "i").test(content)).slice(0, 6);
}

function products(content) {
  return ["Azure", "AWS", "GitHub Actions", "Azure DevOps", "Kubernetes", "PostgreSQL", "Terraform", "OpenTofu", "Docker", "Cosign", "Sigstore"]
    .filter((name) => new RegExp(name.replace(" ", "\\s*"), "i").test(content))
    .slice(0, 6);
}

function escapeCell(value) {
  const normalized = Array.isArray(value) ? value.join(", ") : value;
  return String(normalized ?? "—").replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

function analyze(file) {
  const content = fs.readFileSync(file, "utf8");
  const relative = path.relative(ROOT, file).replace(/\\/g, "/");
  const metadata = parseFrontMatter(content);
  const topic = topicFor(content, relative);
  const languages = codeLanguages(content);
  const riskFlags = [];
  if (!metadata.lastReviewed) riskFlags.push("missing review date");
  if (!/^##+\s+References/im.test(content)) riskFlags.push("no References section");
  if (/tools\.ietf\.org|oauth-security-topics-\d+/i.test(content)) riskFlags.push("obsolete standards URL");
  if (/terraform apply.+drift|dynamodb.+state lock/i.test(content)) riskFlags.push("review Terraform state/drift guidance");
  if (/access keys?.+(?:90 days|rotate)/i.test(content)) riskFlags.push("review long-lived key guidance");
  const linkedValidation = /(?:\]\([^)]*(?:labs?|tests?)[\\/]|`[^`]*(?:labs?|tests?)[\\/])/i.test(content);
  const recommendation = MANUAL_ACTIONS.get(relative)
    || (metadata.reviewStatus === "verified" ? "Maintain on declared review interval." : "Review sources, claims, and examples; retain requires-review until verified.");
  return {
    relative,
    title: metadata.title || firstHeading(content, path.basename(file, ".md")),
    category: metadata.type || relative.split("/")[0],
    date: metadata.date || "not recorded",
    lastReviewed: metadata.lastReviewed || "not recorded",
    readingTime: metadata.readingTime || Math.max(1, Math.ceil(words(content) / 220)),
    primaryTopic: topic.primary,
    secondaryTopics: topic.secondary,
    products: products(content),
    standards: standards(content),
    versions: versions(content),
    references: linkCount(content),
    inlineCitations: /\[[^\]]+\]\(https:\/\//.test(content) ? "yes" : "no",
    runnableCode: languages.some((language) => /^(bash|bicep|csharp|go|hcl|javascript|json|kql|powershell|python|rego|sh|sql|terraform|typescript|yaml)$/i.test(language)) ? "yes" : "no",
    automatedValidation: linkedValidation ? "linked" : "not linked",
    diagrams: /```mermaid|-->|──|┌/.test(content) ? "yes" : "no",
    operationalChecklist: /audit checklist|security checklist|ongoing security review|^\s*- \[[ xX]\]/im.test(content) ? "yes" : "no",
    currency: metadata.reviewStatus || "requires-review",
    factualRisks: riskFlags.join(", ") || "no structural flag",
    flagship: FLAGSHIPS.has(relative) ? "yes" : "no",
    recommendation,
  };
}

function render(items) {
  const generated = new Date().toISOString().slice(0, 10);
  const lines = [
    "# Security Content Inventory",
    "",
    `Generated on ${generated} by \`node scripts/generate-content-inventory.js\`.`,
    "",
    "> This inventory measures repository structure and triage signals. Keyword detection does not verify factual truth, source quality, or code correctness.",
    "",
    `Inventoried pages: **${items.length}**`,
    "",
    "## Field notes",
    "",
    "- Dates and review status are recorded exactly from page-level front matter; missing values are not inherited.",
    "- Reading time is recorded or estimated at 220 prose words per minute.",
    "- Runnable code means a fence declares an executable/configuration language; it does not mean the example was tested.",
    "- Linked validation means the page links a lab or test path; it does not assert the test passed.",
    "- Currency is never inferred from publication date.",
    "",
    "## Complete inventory",
    "",
    "| Path | Title | Category | Published | Last reviewed | Read min | Primary topic | Secondary topics | Products | Standards | Versions | Refs | Inline cites | Runnable code | Automated validation | Diagram | Ops checklist | Currency | Factual-risk flags | Flagship | Action |",
    "| --- | --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
  ];
  for (const item of items) {
    lines.push(`| ${[
      `\`${item.relative}\``, item.title, item.category, item.date, item.lastReviewed,
      item.readingTime, item.primaryTopic, item.secondaryTopics, item.products,
      item.standards, item.versions, item.references, item.inlineCitations,
      item.runnableCode, item.automatedValidation, item.diagrams,
      item.operationalChecklist, item.currency, item.factualRisks,
      item.flagship, item.recommendation,
    ].map(escapeCell).join(" | ")} |`);
  }
  lines.push("");
  return lines.join("\n");
}

const files = CONTENT_ROOTS.flatMap((root) => walk(path.join(ROOT, root)))
  .filter((file) => !EXCLUDED_PREFIXES.some((prefix) => path.relative(ROOT, file).replace(/\\/g, "/").startsWith(prefix)));
const items = [...new Set(files)].sort().map(analyze);
fs.mkdirSync(path.dirname(OUTPUT), { recursive: true });
fs.writeFileSync(OUTPUT, render(items), "utf8");
console.log(`Wrote ${path.relative(ROOT, OUTPUT)} with ${items.length} pages.`);
