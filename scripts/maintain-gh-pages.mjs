import fs from "node:fs";
import path from "node:path";
import {gzipSync} from "node:zlib";
import {fileURLToPath} from "node:url";
import {
  CERTIFICATION_CURRENCY,
  EXPLICIT_ARCHIVED_PATHS,
  REPLACEMENT_PREFIXES,
  REVIEW_DATE,
  REVIEW_TIMESTAMP,
  SITE_ORIGIN,
  STATUS_LABELS,
  entries
} from "./site-config.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const toPosix = value => value.split(path.sep).join("/");
const read = file => fs.readFileSync(path.join(root, file), "utf8");
const write = (file, value) => {
  const target = path.join(root, file);
  fs.mkdirSync(path.dirname(target), {recursive: true});
  fs.writeFileSync(target, value);
};

function listHtml(directory = root) {
  const result = [];
  for (const item of fs.readdirSync(directory, {withFileTypes: true})) {
    if ([".git", "node_modules"].includes(item.name)) continue;
    const full = path.join(directory, item.name);
    if (item.isDirectory()) result.push(...listHtml(full));
    else if (item.isFile() && item.name.endsWith(".html")) result.push(toPosix(path.relative(root, full)));
  }
  return result.sort();
}

function decode(value) {
  return value
    .replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'").replace(/&nbsp;/g, " ")
    .replace(/&#(\d+);/g, (_, code) => String.fromCodePoint(Number(code)))
    .replace(/&#x([0-9a-f]+);/gi, (_, code) => String.fromCodePoint(Number.parseInt(code, 16)));
}

function stripHtml(value) {
  return decode(value.replace(/<script\b[\s\S]*?<\/script>/gi, " ")
    .replace(/<style\b[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim());
}

const escapeHtml = value => String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;")
  .replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

function h1Title(html) {
  const match = html.match(/<h1\b[^>]*>([\s\S]*?)<\/h1>/i);
  return match ? stripHtml(match[1]) : "Untitled page";
}

function pageUrl(file) {
  if (file === "index.html") return "/";
  if (file === "404.html") return "/404.html";
  return `/${file.replace(/index\.html$/i, "")}`;
}

function replacementFor(file) {
  for (const [prefix, replacement] of REPLACEMENT_PREFIXES) {
    if (file.startsWith(prefix) && !entries.has(file)) return replacement;
  }
  return null;
}

function archivedEntry(file, title) {
  const replacement = replacementFor(file);
  return {
    status: "archived",
    indexable: false,
    reviewIntervalDays: 365,
    evidence: ["The public URL is retained to avoid a broken historical link."],
    limitations: ["This page is not current authoritative guidance and is excluded from navigation, search, and sitemap."],
    sources: [],
    runnableEvidence: "None — archived reference",
    proves: "Only that the previous URL has an explicit lifecycle state.",
    notProves: "Technical currency, implementation, or security effectiveness.",
    replacement,
    originalTitle: title.replace(/^(?:Archived reference:\s*)+/i, "")
  };
}

function addDays(dateText, days) {
  const date = new Date(`${dateText}T00:00:00Z`);
  date.setUTCDate(date.getUTCDate() + days);
  return date.toISOString().slice(0, 10);
}

function replaceArticle(html, inner) {
  const opening = /<article\b[^>]*class=["'][^"']*md-content__inner[^"']*md-typeset[^"']*["'][^>]*>/i.exec(html);
  if (!opening) throw new Error("Article container not found");
  const token = /<\/?article\b[^>]*>/gi;
  token.lastIndex = opening.index;
  let depth = 0;
  let item;
  while ((item = token.exec(html))) {
    if (/^<\/article/i.test(item[0])) depth -= 1;
    else depth += 1;
    if (depth === 0) {
      const openEnd = opening.index + opening[0].length;
      const closeStart = item.index;
      return `${html.slice(0, openEnd)}\n${inner.trim()}\n${html.slice(closeStart)}`;
    }
  }
  throw new Error("Article closing tag not found");
}

function removeDivByClass(html, className) {
  const pattern = new RegExp(`<div\\b[^>]*class=["'][^"']*\\b${className}\\b[^"']*["'][^>]*>`, "i");
  const match = pattern.exec(html);
  if (!match) return html;
  const token = /<\/?div\b[^>]*>/gi;
  token.lastIndex = match.index;
  let depth = 0;
  let item;
  while ((item = token.exec(html))) {
    if (/^<\/div/i.test(item[0])) depth -= 1;
    else depth += 1;
    if (depth === 0) return html.slice(0, match.index) + html.slice(token.lastIndex);
  }
  throw new Error(`Unbalanced div while removing ${className}`);
}

function listHtmlItems(items) {
  return `<ul>${items.map(item => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`;
}

function evidenceBlock(entry) {
  const label = entry.label || STATUS_LABELS[entry.status];
  const next = addDays(REVIEW_DATE, entry.reviewIntervalDays);
  return `<!-- portfolio-evidence:start -->
<aside class="content-evidence content-evidence--${entry.status}" aria-label="Content evidence status">
  <strong>${escapeHtml(label)}</strong>
  <dl>
    <dt>Last reviewed</dt><dd>${REVIEW_DATE}</dd>
    <dt>Validated evidence</dt><dd>${listHtmlItems(entry.evidence)}</dd>
    <dt>Not established</dt><dd>${listHtmlItems(entry.limitations)}</dd>
    <dt>Review cadence</dt><dd>Every ${entry.reviewIntervalDays} days; next review due ${next}.</dd>
  </dl>
</aside>
<!-- portfolio-evidence:end -->`;
}

const nav = `<!-- portfolio-nav:start -->
<nav class="portfolio-nav" aria-label="Portfolio navigation">
  <div class="portfolio-nav__inner">
    <a class="portfolio-nav__brand" href="/">Jason Achkar Diab · Security Engineering</a>
    <ul class="portfolio-nav__items">
      <li><a href="/">Home</a></li>
      <li><details><summary>Engineering</summary><ul class="portfolio-nav__menu">
        <li><a href="/devsecops/secure-cicd-pipeline-design/">Secure CI/CD trust boundaries</a></li>
        <li><a href="/appsec/saas-multitenancy-isolation/">Multi-tenant SaaS isolation</a></li>
        <li><a href="/appsec/ai-agent-security/">AI-agent authorization</a></li>
        <li><a href="/cloud-security/iam-at-scale/">IAM and workload federation</a></li>
        <li><a href="/appsec/oauth2-oidc-deep-dive/">OAuth 2.0 and OIDC</a></li>
        <li><a href="/cloud-security/kubernetes-multi-tenancy/">Kubernetes isolation</a></li>
        <li><a href="/devsecops/iac-security-and-policy-as-code/">IaC policy engineering</a></li>
        <li><a href="/devsecops/supply-chain-sbom-signing/">Supply-chain evidence</a></li>
        <li><a href="/devsecops/secureobs-multitenant-security-scanner/">SecureObs architecture</a></li>
        <li><a href="/threat-intel/cloud-breach-case-studies/">Incident case studies</a></li>
      </ul></details></li>
      <li><a href="/#validated-labs">Labs</a></li>
      <li><a href="/docs/research-audit/content-inventory/">Evidence registry</a></li>
      <li><a href="/about/quality-methodology/">Methodology</a></li>
      <li><a href="/#study-notes">Study notes</a></li>
    </ul>
  </div>
</nav>
<!-- portfolio-nav:end -->`;

const footerProof = `<!-- portfolio-footer:start -->
<section class="portfolio-footer-proof" aria-label="Publication provenance">
  <ul>
    <li><strong>Publication target:</strong> gh-pages</li>
    <li><strong>Review branch:</strong> <a href="https://github.com/jasonachkar/cybersecurity-writeups/tree/codex/validated-gh-pages-deployment">codex/validated-gh-pages-deployment</a></li>
    <li><strong>Draft deployment review:</strong> <a href="https://github.com/jasonachkar/cybersecurity-writeups/pull/5">PR #5</a></li>
    <li><strong>Last content review:</strong> ${REVIEW_DATE}</li>
  </ul>
</section>
<!-- portfolio-footer:end -->`;

function homeBody() {
  const cards = [
    ["Secure CI/CD trust boundaries", "/devsecops/secure-cicd-pipeline-design/", "Workflow identity, untrusted validation, protected build and attestation policy.", "Partially verified · tested gate fixtures"],
    ["Multi-tenant SaaS isolation", "/appsec/saas-multitenancy-isolation/", "Authorization across API, database, pool, cache, queue, storage and telemetry boundaries.", "Partially tested investigation"],
    ["AI-agent authorization", "/appsec/ai-agent-security/", "External authorization, action-bound approval, concurrent local consumption, and bounded tool execution.", "Partially verified · tested broker"],
    ["IAM and workload federation", "/cloud-security/iam-at-scale/", "Issuer, audience, subject, delegation, PassRole and permission-boundary decisions.", "Partially verified · policy fixtures"],
    ["OAuth 2.0 and OIDC", "/appsec/oauth2-oidc-deep-dive/", "Exact redirects, PKCE, state, nonce, token audience, JWKS and resource authorization.", "Partially verified · token fixtures"],
    ["Kubernetes isolation", "/cloud-security/kubernetes-multi-tenancy/", "Namespace, workload identity, network, admission, image and operational failure boundaries.", "Partially verified · image integration partial"],
    ["IaC policy engineering", "/devsecops/iac-security-and-policy-as-code/", "Unknown values, deleted controls, plan semantics, policy failure and rollout design.", "Partially verified · plan fixtures"],
    ["Supply-chain evidence", "/devsecops/supply-chain-sbom-signing/", "Artifact bytes, SBOM, provenance, signer, builder, source and policy kept distinct.", "Partially tested · no crypto integration"],
    ["SecureObs architecture", "/devsecops/secureobs-multitenant-security-scanner/", "Owner-confirmed architecture separated from reproduced patterns and future controls.", "Partially verified · sanitized scope"],
    ["Incident case studies", "/threat-intel/cloud-breach-case-studies/", "Owner disclosures, chronology, inference limits, control lessons and residual uncertainty.", "Partially verified · public evidence"]
  ];
  return `<section class="portfolio-hero">
  <p class="portfolio-hero__kicker">Evidence-first security engineering</p>
  <h1 id="security-engineering-decisions-you-can-audit">Security engineering decisions you can audit.</h1>
  <p class="portfolio-hero__lede">Threat models, enforcement points, negative tests and residual risk across cloud identity, application security, delivery pipelines, Kubernetes, detection and software supply chains—without turning a local test into a production claim.</p>
  <div class="portfolio-actions"><a class="portfolio-button portfolio-button--primary" href="#featured-engineering">Review engineering work</a><a class="portfolio-button" href="/docs/research-audit/content-inventory/">Inspect the evidence registry</a></div>
</section>
<section class="portfolio-facts" aria-label="Review facts"><div class="portfolio-fact"><strong>gh-pages</strong><span>Publication target</span></div><div class="portfolio-fact"><strong>PR #5</strong><span>Draft deployment review</span></div><div class="portfolio-fact"><strong>${REVIEW_DATE}</strong><span>Content review date</span></div><div class="portfolio-fact"><strong>Page-level</strong><span>Evidence and limitation disclosure</span></div></section>
<section aria-labelledby="featured-engineering"><h2 id="featured-engineering">Featured engineering investigations</h2><p>Each page leads with what was checked, what was executed, what remains untested, and when it must be reviewed again.</p><div class="portfolio-grid">${cards.map(([title, href, copy, status]) => `<div class="portfolio-card"><span class="portfolio-card__status">${status}</span><h3>${title}</h3><p>${copy}</p><a class="portfolio-card__link" href="${href}">Open investigation →</a></div>`).join("")}</div></section>
<section aria-labelledby="validated-labs"><h2 id="validated-labs">Runnable evidence</h2><p>Repository labs exercise bounded decisions; their status blocks distinguish local models and structural checks from native platform or cryptographic integration.</p><ul><li><a href="/labs/secure-cicd/">Secure CI/CD gate and workflow fixtures</a></li><li><a href="/labs/iam-oidc/">IAM and workload-identity decision cases</a></li><li><a href="/labs/oauth-oidc/">OAuth/OIDC token-boundary cases</a></li><li><a href="/labs/ai-agent-security/">AI external tool-broker cases</a></li><li><a href="/labs/postgresql-rls/">PostgreSQL row-level security</a></li><li><a href="/labs/kubernetes-security/">Kubernetes policy and image-decision fixtures</a></li><li><a href="/labs/supply-chain/">Offline provenance and SBOM policy</a></li><li><a href="/labs/iac-policy/">Terraform plan and Rego fixtures</a></li><li><a href="/labs/azure-landing-zone/">Azure landing-zone Bicep boundary</a></li></ul></section>
<section aria-labelledby="study-notes"><h2 id="study-notes">Study notes</h2><p>Certification collections are visibly separated from implementation evidence and tied to their official owner material.</p><ul><li><a href="/docs/certification-notes/az-900/">Microsoft AZ-900</a></li><li><a href="/docs/certification-notes/sc-500/">Microsoft SC-500</a></li><li><a href="/docs/certification-notes/security-plus/">CompTIA Security+ SY0-701</a></li><li><a href="/docs/certification-notes/google-cybersecurity/">Google Cybersecurity Certificate</a></li></ul></section>`;
}

function provenanceBody() {
  return `<h1 id="site-provenance">Site provenance</h1><p>This page describes the static artifact reviewed in draft PR #5. It does not claim that an unmerged commit is already deployed.</p><table><thead><tr><th scope="col">Field</th><th scope="col">Value</th></tr></thead><tbody><tr><th scope="row">Canonical site</th><td><a href="${SITE_ORIGIN}">${SITE_ORIGIN}</a></td></tr><tr><th scope="row">Repository</th><td><a href="https://github.com/jasonachkar/cybersecurity-writeups">jasonachkar/cybersecurity-writeups</a></td></tr><tr><th scope="row">Artifact</th><td>Static GitHub Pages site</td></tr><tr><th scope="row">Publication target</th><td><code>gh-pages</code></td></tr><tr><th scope="row">Review branch</th><td><a href="https://github.com/jasonachkar/cybersecurity-writeups/tree/codex/validated-gh-pages-deployment"><code>codex/validated-gh-pages-deployment</code></a></td></tr><tr><th scope="row">Draft review</th><td><a href="https://github.com/jasonachkar/cybersecurity-writeups/pull/5">PR #5</a></td></tr><tr><th scope="row">Content review timestamp</th><td><time datetime="${REVIEW_TIMESTAMP}">${REVIEW_TIMESTAMP}</time></td></tr></tbody></table><h2 id="integrity-boundary">Integrity boundary</h2><p><code>CNAME</code> and <code>.nojekyll</code> remain part of the publication artifact. A manually embedded source SHA would become stale as soon as it was committed, so this branch does not pretend a static file can identify its own final deployment commit. The machine-readable review context is <a href="/site-meta.json"><code>site-meta.json</code></a>.</p><h2 id="what-build-evidence-means">What this evidence means</h2><p>Static validation establishes the checked properties recorded in the validation report. It does not establish cloud deployment, customer use, production availability, or complete security. Each maintained page states its narrower evidence and residual limitations.</p>`;
}

function qualityBody() {
  return `<h1 id="evidence-and-quality-methodology">Evidence and quality methodology</h1><p>The portfolio treats security guidance as an engineering artifact. Status is visible on the page, represented in <a href="/content-status.json"><code>content-status.json</code></a>, and used to drive navigation, search and sitemap inclusion.</p><h2 id="evidence-statuses">Evidence statuses</h2><dl><dt>Verified engineering investigation</dt><dd>Material current-state claims were checked against named primary sources. Examples can still be only partly tested.</dd><dt>Partially verified engineering investigation</dt><dd>Primary-source review covers a bounded area while one or more platform or implementation boundaries remain untested.</dd><dt>Validated lab</dt><dd>The documented positive and negative behavior executed in the stated environment.</dd><dt>Partially tested lab</dt><dd>Only structural, offline, schema or pedagogical-model behavior executed.</dd><dt>Conceptual reference</dt><dd>Architecture or method without end-to-end runtime validation.</dd><dt>Study notes</dt><dd>Owner-aligned learning material, never implementation evidence.</dd><dt>Archived</dt><dd>URL retained for continuity but excluded from normal discovery and unsafe as current guidance.</dd></dl><h2 id="source-hierarchy">Source hierarchy</h2><ol><li>Standards bodies and final specifications.</li><li>Platform-owner documentation and source repositories.</li><li>Incident-owner disclosures, court or regulator records.</li><li>Secondary analysis only when primary material cannot answer the question, labelled accordingly.</li></ol><h2 id="validation-approach">Validation approach</h2><p>The branch validator checks canonical URLs, robots state, one title and H1, evidence blocks, duplicate IDs, internal files and fragments, local assets, external-link safety attributes, JSON, sitemap/search set equality, provenance and known misleading strings. Runnable labs are executed separately with their available native tools. Missing external tools remain limitations.</p><h2 id="review-intervals">Review intervals</h2><p>Most engineering investigations use a 90-day interval. Rapidly evolving agent/MCP work and publication metadata use 30 days. Certification notes are rechecked against the owner material; a displayed review date is not proof of correctness.</p><h2 id="limitations">Limitations</h2><p>Automated accessibility and structural checks find important classes of defects but do not replace keyboard, assistive-technology, threat-model, platform or human editorial review. A passing finite suite proves only its declared cases.</p>`;
}

function securityPlusBody() {
  return `<h1 id="comptia-security-plus-sy0-701-study-notes">CompTIA Security+ SY0-701 study notes</h1><p>These notes are a current-orientation page, not exam questions, an official course, or implementation evidence. The maintained outline follows the five owner-defined domains without retaining incomplete legacy domain pages.</p><ol><li>General Security Concepts</li><li>Threats, Vulnerabilities, and Mitigations</li><li>Security Architecture</li><li>Security Operations</li><li>Security Program Management and Oversight</li></ol><h2 id="use-with-official-objectives">Use with the official objectives</h2><p>Start with the <a href="https://www.comptia.org/en-us/certifications/security/">official CompTIA Security+ page</a> and its current SY0-701 objectives. This page intentionally omits percentages rather than carrying an unverified or stale copy.</p><h2 id="engineering-cross-references">Engineering cross-references</h2><ul><li><a href="/cloud-security/iam-at-scale/">IAM and workload identity</a></li><li><a href="/cloud-security/cloud-network-segmentation/">Network segmentation and egress</a></li><li><a href="/cloud-security/cloud-detection-and-response/">Detection and response</a></li><li><a href="/devsecops/secure-cicd-pipeline-design/">Secure CI/CD</a></li></ul>`;
}

function slug(value) {
  return value.toLowerCase().normalize("NFKD").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "archived";
}

function archiveBody(entry) {
  const title = entry.originalTitle || "Previous content";
  const link = entry.replacement
    ? `<p><a class="portfolio-button portfolio-button--primary" href="${entry.replacement}">Open the maintained replacement</a></p>`
    : `<p><a class="portfolio-button" href="/docs/research-audit/content-inventory/">Review maintained evidence</a></p>`;
  return `<h1 id="archived-reference-${slug(title)}">Archived reference: ${escapeHtml(title)}</h1><section class="archive-notice" aria-label="Archive notice"><strong>This page is not current security guidance.</strong><p>The URL is preserved for continuity, but the previous material was removed from navigation, search and sitemap because its claims were duplicated, superseded or not reviewed to the portfolio's current evidence standard.</p>${link}</section><h2 id="archive-behavior">Archive behavior</h2><ul><li>Search engines receive an explicit <code>noindex</code> directive.</li><li>The page cannot appear in portfolio search or normal navigation.</li><li>No implementation, test result or technical currency is implied.</li></ul>`;
}

function registryBody(records) {
  const rows = [...entries.entries()].filter(([, entry]) => ["verified", "partially-verified", "validated-lab", "partially-tested"].includes(entry.status));
  return `<h1 id="evidence-registry">Evidence Registry</h1><p>This registry is generated from explicit public-URL metadata. It does not infer topics from keywords or interpret arbitrary numbers as versions. Read each linked page for the full trust assumptions, enforcement points, failure behavior and residual risk.</p><div class="md-typeset__scrollwrap"><div class="md-typeset__table"><table class="evidence-registry"><thead><tr><th scope="col">Investigation</th><th scope="col">Public URL</th><th scope="col">Evidence status</th><th scope="col">Last reviewed</th><th scope="col">Primary sources</th><th scope="col">Runnable evidence</th><th scope="col">What the evidence proves</th><th scope="col">What it does not prove</th><th scope="col">Next review date</th></tr></thead><tbody>${rows.map(([file, entry]) => { const record = records.get(file); const url = pageUrl(file); return `<tr><th scope="row"><a href="${url}">${escapeHtml(record.title)}</a></th><td><code>${url}</code></td><td>${escapeHtml(entry.label || STATUS_LABELS[entry.status])}</td><td>${REVIEW_DATE}</td><td>${entry.sources.length ? listHtmlItems(entry.sources) : "Page reference section"}</td><td>${escapeHtml(entry.runnableEvidence)}</td><td>${escapeHtml(entry.proves)}</td><td>${escapeHtml(entry.notProves)}</td><td>${addDays(REVIEW_DATE, entry.reviewIntervalDays)}</td></tr>`; }).join("")}</tbody></table></div></div><h2 id="interpretation">Interpretation</h2><p>A passing finite test establishes only the declared cases. Schema validation is not a native admission test, an offline verifier adapter is not cryptographic verification, and an architecture investigation is not a production deployment.</p>`;
}

function articleToc(html, entry) {
  if (entry.status === "archived") return "";
  const article = html.match(/<article\b[^>]*>([\s\S]*?)<\/article>/i)?.[1] || "";
  const headings = [];
  for (const match of article.matchAll(/<h2\b[^>]*id=["']([^"']+)["'][^>]*>([\s\S]*?)<\/h2>/gi)) {
    const title = stripHtml(match[2]);
    if (title && !headings.some(item => item.id === match[1])) headings.push({id: match[1], title});
  }
  if (headings.length < 3) return "";
  return `<!-- portfolio-toc:start --><nav class="article-toc" aria-label="On this page"><strong>On this page</strong><ol>${headings.slice(0, 16).map(item => `<li><a href="#${escapeHtml(item.id)}">${escapeHtml(item.title)}</a></li>`).join("")}</ol></nav><!-- portfolio-toc:end -->`;
}

function normalizePage(file, html, entry) {
  html = html.replace(/<!-- portfolio-nav:start -->[\s\S]*?<!-- portfolio-nav:end -->\s*/g, "")
    .replace(/<!-- portfolio-footer:start -->[\s\S]*?<!-- portfolio-footer:end -->\s*/g, "")
    .replace(/<!-- portfolio-evidence:start -->[\s\S]*?<!-- portfolio-evidence:end -->\s*/g, "")
    .replace(/<!-- portfolio-toc:start -->[\s\S]*?<!-- portfolio-toc:end -->\s*/g, "")
    .replace(/<aside\b[^>]*class=["'][^"']*content-evidence[^"']*["'][^>]*>[\s\S]*?<\/aside>\s*/gi, "")
    .replace(/<aside\b[^>]*class=["'][^"']*study-currency[^"']*["'][^>]*>[\s\S]*?<\/aside>\s*/gi, "");

  // Material's source widget fetches GitHub API repo facts on every page load; the
  // repository has no releases, so /releases/latest returns 404 and logs a console
  // error. Dropping the component hook keeps the repo link without the API fetch.
  html = html.replace(/(class="md-source") data-md-component="source"/g, "$1");

  // Material's search dialog has role="dialog" without an accessible name.
  html = html.replace(/(<div class="md-search"[^>]*role="dialog")(?![^>]*aria-label)/g, '$1 aria-label="Site search"');

  // MkDocs line-number anchors are empty focusable links with a deprecated name attribute.
  html = html.replace(/<a id="__codelineno-[^"]*" name="__codelineno-[^"]*" href="#__codelineno-[^"]*"><\/a>/g, "");
  // Header topic spans from the original generator can carry unencoded ampersands.
  html = html.replace(/<span class="md-ellipsis">[\s\S]*?<\/span>/g,
    segment => segment.replace(/&(?!amp;|lt;|gt;|quot;|apos;|#)/g, "&amp;"));

  html = html.replaceAll("Jason Achkardiab", "Jason Achkar Diab")
    .replace(/<link\b[^>]*(?:fonts\.googleapis\.com|fonts\.gstatic\.com|font-awesome|cdnjs\.cloudflare\.com)[^>]*>\s*/gi, "")
    .replace(/<style>\s*:root\{--md-text-font:[\s\S]*?<\/style>\s*/gi, "")
    .replace(/<i\b[^>]*class=["'][^"']*\bfa(?:s|r|b|-)[^"']*["'][^>]*><\/i>\s*/gi, "")
    .replace(/<link\b[^>]*rel=["'](?:prev|next)["'][^>]*>\s*/gi, "")
    .replace(/<link\b[^>]*rel=["']canonical["'][^>]*>\s*/gi, "")
    .replace(/<meta\b[^>]*name=["']robots["'][^>]*>\s*/gi, "");

  html = html.replace(/<link\b[^>]*href=["'][^"']*css\/portfolio\.css["'][^>]*>\s*/gi, "");
  const customCss = html.match(/<link\b[^>]*href=["']([^"']*css\/custom\.css)["'][^>]*>/i);
  if (!customCss) throw new Error(`${file}: custom stylesheet link not found`);
  const portfolioHref = customCss[1].replace(/custom\.css$/, "portfolio.css");
  html = html.replace(customCss[0], `${customCss[0]}\n<link rel="stylesheet" href="${portfolioHref}">`);

  html = removeDivByClass(html, "md-sidebar--primary");
  html = removeDivByClass(html, "md-sidebar--secondary");

  html = html.replace(/<meta\b[^>]*name=["']author["'][^>]*>/i, '<meta name="author" content="Jason Achkar Diab">');
  if (!/<meta\b[^>]*name=["']author["']/i.test(html)) html = html.replace(/<\/head>/i, '  <meta name="author" content="Jason Achkar Diab">\n</head>');

  const canonicalPath = entry.replacement || pageUrl(file);
  const canonical = `${SITE_ORIGIN}${canonicalPath === "/" ? "/" : canonicalPath}`;
  const robots = entry.indexable ? "index, follow" : (entry.replacement ? "noindex, follow" : "noindex, nofollow");
  html = html.replace(/<\/head>/i, `  <link rel="canonical" href="${canonical}">\n  <meta name="robots" content="${robots}">\n</head>`);

  const title = h1Title(html);
  html = html.replace(/<title>[\s\S]*?<\/title>/i, `<title>${escapeHtml(title)} | Jason Achkar Diab</title>`);
  html = html.replace(/<\/header>/i, `</header>\n${nav}`);

  html = html.replace(/<div class="md-copyright">[\s\S]*?<div class="md-copyright__highlight site-provenance"[\s\S]*?<\/div>\s*<\/div>/i,
    '<div class="md-copyright">&copy; 2026 Jason Achkar Diab. Security guidance is scoped by page-level evidence.</div>');
  html = html.replace(/<footer\b([^>]*)>/i, `<footer$1>\n${footerProof}`);

  const evidence = evidenceBlock(entry);
  html = html.replace(/<h1\b[^>]*>[\s\S]*?<\/h1>/i, match => `${match}\n${evidence}`);

  const currency = CERTIFICATION_CURRENCY.find(([prefix]) => file.startsWith(prefix));
  if (currency && entry.status === "study-notes") {
    const banner = `<aside class="study-currency" aria-label="Official guide currency"><strong>Official-owner check</strong><p>${currency[1]}</p></aside>`;
    html = html.replace("<!-- portfolio-evidence:end -->", `<!-- portfolio-evidence:end -->\n${banner}`);
  }

  const toc = articleToc(html, entry);
  if (toc) html = html.replace("<!-- portfolio-evidence:end -->", `<!-- portfolio-evidence:end -->\n${toc}`);

  const h1Id = html.match(/<h1\b[^>]*id=["']([^"']+)["']/i)?.[1];
  if (h1Id) html = html.replace(/href=["']#[^"']*["'](?=\s+class=["']md-skip["'])/i, `href="#${h1Id}"`);
  if (!/class=["']md-skip["']/.test(html)) {
    html = html.replace(/<body\b[^>]*>/i, match => `${match}\n<a href="#${h1Id || ""}" class="md-skip">Skip to content</a>`);
  }
  return html;
}

const qualityPath = "about/quality-methodology/index.html";
if (!fs.existsSync(path.join(root, qualityPath))) {
  const source = path.join(root, "about/site-provenance/index.html");
  fs.mkdirSync(path.dirname(path.join(root, qualityPath)), {recursive: true});
  fs.copyFileSync(source, path.join(root, qualityPath));
}

const files = listHtml();
const classifiedPaths = new Set([...entries.keys(), ...EXPLICIT_ARCHIVED_PATHS]);
for (const file of files) if (!classifiedPaths.has(file)) throw new Error(`Unclassified HTML page: ${file}`);
for (const archived of EXPLICIT_ARCHIVED_PATHS) {
  if (!files.includes(archived)) throw new Error(`Explicit archived page is missing: ${archived}`);
}

for (const configured of entries.keys()) {
  if (!files.includes(configured)) throw new Error(`Configured page is missing: ${configured}`);
}

const records = new Map(files.map(file => {
  const html = read(file);
  const title = h1Title(html);
  const entry = entries.get(file) || archivedEntry(file, title);
  return [file, {file, title, entry}];
}));

for (const record of records.values()) {
  let html = read(record.file);
  if (record.file === "index.html") html = replaceArticle(html, homeBody());
  else if (record.file === "about/site-provenance/index.html") html = replaceArticle(html, provenanceBody());
  else if (record.file === qualityPath) html = replaceArticle(html, qualityBody());
  else if (record.file === "docs/research-audit/content-inventory/index.html") html = replaceArticle(html, registryBody(records));
  else if (record.file === "docs/certification-notes/security-plus/index.html") html = replaceArticle(html, securityPlusBody());
  else if (!record.entry.indexable) html = replaceArticle(html, archiveBody(record.entry));
  html = normalizePage(record.file, html, record.entry);
  write(record.file, html);
  record.title = h1Title(html);
}

const manifest = {};
for (const [file, record] of records) {
  manifest[pageUrl(file)] = {
    title: record.title,
    status: record.entry.status,
    lastReviewed: REVIEW_DATE,
    evidence: record.entry.evidence,
    limitations: record.entry.limitations,
    reviewIntervalDays: record.entry.reviewIntervalDays
  };
}
write("content-status.json", `${JSON.stringify(manifest, null, 2)}\n`);

const searchDocs = [];
for (const [file, entry] of entries) {
  if (!entry.indexable) continue;
  const html = read(file);
  const article = html.match(/<article\b[^>]*>([\s\S]*?)<\/article>/i)?.[1] || "";
  searchDocs.push({
    location: file === "index.html" ? "" : file.replace(/index\.html$/, ""),
    title: records.get(file).title,
    text: stripHtml(article).slice(0, 40000),
    tags: entry.tags.join(" ")
  });
}
const searchIndex = {
  config: {lang: ["en"], separator: "[\\s\\-]+", pipeline: ["stopWordFilter"], fields: {title: {boost: 1000}, text: {boost: 1}, tags: {boost: 1000000}}},
  docs: searchDocs
};
write("search/search_index.json", `${JSON.stringify(searchIndex)}\n`);

const sitemapUrls = [...entries.keys()].filter(file => entries.get(file).indexable).map(file => {
  const loc = `${SITE_ORIGIN}${pageUrl(file)}`;
  const status = entries.get(file).status;
  const priority = file === "index.html" ? "1.0" : status === "study-notes" ? "0.4" : status.includes("lab") || status === "partially-tested" ? "0.7" : "0.8";
  return `  <url><loc>${loc}</loc><lastmod>${REVIEW_DATE}</lastmod><changefreq>monthly</changefreq><priority>${priority}</priority></url>`;
});
const sitemap = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${sitemapUrls.join("\n")}\n</urlset>\n`;
write("sitemap.xml", sitemap);
fs.writeFileSync(path.join(root, "sitemap.xml.gz"), gzipSync(Buffer.from(sitemap), {level: 9, mtime: 0}));

const legacyMetadataNotice = {
  deprecated: true,
  statusAuthority: "/content-status.json",
  keyType: "public URL",
  reason: "This gh-pages artifact no longer uses Markdown-source-path review flags as a public status authority.",
  migratedAt: REVIEW_TIMESTAMP
};
write("docs/content-metadata.json", `${JSON.stringify(legacyMetadataNotice, null, 2)}\n`);

const siteMeta = {
  site: SITE_ORIGIN,
  repository: "jasonachkar/cybersecurity-writeups",
  publicationTarget: "gh-pages",
  reviewBranch: "codex/validated-gh-pages-deployment",
  pullRequest: 5,
  artifactType: "static GitHub Pages site",
  contentReviewTimestamp: REVIEW_TIMESTAMP,
  evidenceModel: "page-level status and validation disclosures"
};
write("site-meta.json", `${JSON.stringify(siteMeta, null, 2)}\n`);

const indexableCount = [...records.values()].filter(item => item.entry.indexable).length;
console.log(`Maintained ${records.size} HTML pages: ${indexableCount} indexable, ${records.size - indexableCount} archived.`);
console.log(`Generated ${Object.keys(manifest).length} status records, ${searchDocs.length} search records, and ${sitemapUrls.length} sitemap URLs.`);
