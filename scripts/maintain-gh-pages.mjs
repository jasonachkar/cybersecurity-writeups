import fs from "node:fs";
import path from "node:path";
import {gzipSync} from "node:zlib";
import {fileURLToPath} from "node:url";
import {
  CERTIFICATION_CURRENCY,
  EXPLICIT_ARCHIVED_PATHS,
  NAV_INDEX,
  NAV_ORDER,
  NAV_TREE,
  REPLACEMENT_PREFIXES,
  REVIEW_DATE,
  REVIEW_TIMESTAMP,
  SITE_ORIGIN,
  STATUS_LABELS,
  entries
} from "./site-config.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const toPosix = value => value.split(path.sep).join("/");
// Normalized on both ends so the script produces identical LF-only output no matter
// whether the working tree was checked out with core.autocrlf converting to CRLF.
const read = file => fs.readFileSync(path.join(root, file), "utf8").replace(/\r\n/g, "\n");
const write = (file, value) => {
  const target = path.join(root, file);
  fs.mkdirSync(path.dirname(target), {recursive: true});
  fs.writeFileSync(target, value.replace(/\r\n/g, "\n"));
};

function listHtml(directory = root) {
  const result = [];
  for (const item of fs.readdirSync(directory, {withFileTypes: true})) {
    if ([".git", "node_modules", ".tools", ".venv", ".idea", "mkdocs-project"].includes(item.name)) continue;
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

function formatLongDate(dateText) {
  const date = new Date(`${dateText}T00:00:00Z`);
  return date.toLocaleDateString("en-US", {month: "long", day: "numeric", year: "numeric", timeZone: "UTC"});
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

function findDivBoundsByClass(html, className) {
  const pattern = new RegExp(`<div\\b[^>]*class=["'][^"']*\\b${className}\\b[^"']*["'][^>]*>`, "i");
  const match = pattern.exec(html);
  if (!match) return null;
  const token = /<\/?div\b[^>]*>/gi;
  token.lastIndex = match.index;
  let depth = 0;
  let item;
  while ((item = token.exec(html))) {
    if (/^<\/div/i.test(item[0])) depth -= 1;
    else depth += 1;
    if (depth === 0) {
      return {openStart: match.index, openEnd: match.index + match[0].length, closeStart: item.index, closeEnd: token.lastIndex};
    }
  }
  throw new Error(`Unbalanced div while locating ${className}`);
}

function wrapDivByClass(html, className, before, after) {
  const bounds = findDivBoundsByClass(html, className);
  if (!bounds) throw new Error(`div.${className} not found`);
  return html.slice(0, bounds.openStart) + before + html.slice(bounds.openStart, bounds.closeEnd) + after + html.slice(bounds.closeEnd);
}

function insertBeforeArticleClose(html, inner) {
  const idx = html.lastIndexOf("</article>");
  if (idx === -1) throw new Error("No </article> closing tag found");
  // Trim trailing whitespace from the "before" half first, otherwise the original
  // indentation that used to sit directly in front of </article> is orphaned onto
  // its own now-blank line.
  const before = html.slice(0, idx).replace(/[ \t]+$/, "");
  return `${before}\n${inner}\n${html.slice(idx)}`;
}

function listHtmlItems(items) {
  return `<ul>${items.map(item => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`;
}

// ---------------------------------------------------------------------------
// Generated documentation-shell components. Each is wrapped in its own
// idempotent HTML-comment marker pair so `stripGenerated()` (used both to
// clean a page before re-injecting and to fingerprint article prose for the
// content-preservation check below) can remove exactly what this script adds.
// ---------------------------------------------------------------------------

function stripGenerated(html) {
  return html
    // Legacy markers from the previous single-bar portfolio chrome (one-time cleanup).
    .replace(/<!-- portfolio-nav:start -->[\s\S]*?<!-- portfolio-nav:end -->\s*/g, "")
    .replace(/<!-- portfolio-footer:start -->[\s\S]*?<!-- portfolio-footer:end -->\s*/g, "")
    .replace(/<!-- portfolio-evidence:start -->[\s\S]*?<!-- portfolio-evidence:end -->\s*/g, "")
    .replace(/<!-- portfolio-toc:start -->[\s\S]*?<!-- portfolio-toc:end -->\s*/g, "")
    // Current documentation-shell markers.
    .replace(/<!-- docs-left-nav:start -->[\s\S]*?<!-- docs-left-nav:end -->\s*/g, "")
    .replace(/<!-- docs-breadcrumbs:start -->[\s\S]*?<!-- docs-breadcrumbs:end -->\s*/g, "")
    // These three are inserted with an explicit leading "\n" by the code below (so the
    // strip must eat it too), but never with trailing whitespace of our own — whatever
    // follows in the template belongs to the original page, not to us.
    .replace(/\n?<!-- docs-evidence:start -->[\s\S]*?<!-- docs-evidence:end -->/g, "")
    // No trailing \s* here: unlike the others, whatever follows this marker in the
    // template (e.g. the tab-hash <script>) is original content, not ours to eat.
    .replace(/<!-- docs-toc:start -->[\s\S]*?<!-- docs-toc:end -->/g, "")
    .replace(/\n?<!-- docs-prevnext:start -->[\s\S]*?<!-- docs-prevnext:end -->\s*/g, "")
    // No trailing \s* here either: what follows in the template (the footer-meta div)
    // is original content, not ours to eat.
    .replace(/\n?<!-- docs-footer:start -->[\s\S]*?<!-- docs-footer:end -->/g, "")
    .replace(/<aside\b[^>]*class=["'][^"']*content-evidence[^"']*["'][^>]*>[\s\S]*?<\/aside>/gi, "")
    // Also inserted with a leading "\n" and no trailing whitespace of its own (see above).
    .replace(/\n?<aside\b[^>]*class=["'][^"']*study-currency[^"']*["'][^>]*>[\s\S]*?<\/aside>/gi, "");
}

function evidenceSummary(entry) {
  const label = entry.label || STATUS_LABELS[entry.status];
  const next = addDays(REVIEW_DATE, entry.reviewIntervalDays);
  const evidenceCount = entry.evidence.length;
  const limitationCount = entry.limitations.length;
  return `<!-- docs-evidence:start -->
<aside class="content-evidence content-evidence--${entry.status}" aria-label="Content evidence status">
  <div class="docs-evidence-row">
    <strong class="docs-evidence-row__status">${escapeHtml(label)}</strong>
    <span class="docs-evidence-row__item">Last reviewed: ${escapeHtml(formatLongDate(REVIEW_DATE))}</span>
    <span class="docs-evidence-row__item">${evidenceCount} validated ${evidenceCount === 1 ? "check" : "checks"}</span>
    <span class="docs-evidence-row__item">${limitationCount} ${limitationCount === 1 ? "limitation" : "limitations"}</span>
    <span class="docs-evidence-row__item">Next review: ${escapeHtml(formatLongDate(next))}</span>
  </div>
  <details class="docs-evidence-detail">
    <summary>View evidence and limitations</summary>
    <dl>
      <dt>Validated evidence</dt><dd>${listHtmlItems(entry.evidence)}</dd>
      <dt>Not established</dt><dd>${listHtmlItems(entry.limitations)}</dd>
      <dt>Review cadence</dt><dd>Every ${entry.reviewIntervalDays} days; next review due ${next}.</dd>
    </dl>
  </details>
</aside>
<!-- docs-evidence:end -->`;
}

function breadcrumbs(currentUrl) {
  const record = NAV_INDEX.get(currentUrl);
  if (!record) return "";
  const items = [`<li><a href="/">Home</a></li>`];
  for (const ancestor of record.trail) items.push(`<li>${escapeHtml(ancestor.title)}</li>`);
  items.push(`<li aria-current="page">${escapeHtml(record.title)}</li>`);
  return `<!-- docs-breadcrumbs:start --><nav class="docs-breadcrumbs" aria-label="Breadcrumb"><ol>${items.join("")}</ol></nav><!-- docs-breadcrumbs:end -->`;
}

function prevNext(currentUrl) {
  const index = NAV_ORDER.indexOf(currentUrl);
  if (index === -1) return "";
  const prevUrl = index > 0 ? NAV_ORDER[index - 1] : null;
  const nextUrl = index < NAV_ORDER.length - 1 ? NAV_ORDER[index + 1] : null;
  if (!prevUrl && !nextUrl) return "";
  const link = (url, direction) => {
    if (!url) return "";
    const record = NAV_INDEX.get(url);
    const group = record.trail.length ? record.trail[record.trail.length - 1].title : "Documentation";
    const order = direction === "prev" ? "&larr; Previous" : "Next &rarr;";
    return `<a class="docs-prevnext__link docs-prevnext__link--${direction}" href="${url}"><span class="docs-prevnext__dir">${order}</span><span class="docs-prevnext__cat">${escapeHtml(group)}</span><span class="docs-prevnext__title">${escapeHtml(record.title)}</span></a>`;
  };
  return `<!-- docs-prevnext:start --><nav class="docs-prevnext" aria-label="Page navigation">${link(prevUrl, "prev")}${link(nextUrl, "next")}</nav><!-- docs-prevnext:end -->`;
}

function navContainsCurrent(node, currentUrl) {
  if (node.href === currentUrl) return true;
  if (node.children) return node.children.some(child => navContainsCurrent(child, currentUrl));
  return false;
}

function renderNavNode(node, currentUrl) {
  if (node.href) {
    // A leaf link. AZ-900/SC-500 also carry `children` (their exam domains) so
    // breadcrumbs/prev-next can walk into them, but the left nav intentionally
    // stays flat here, matching the requested navigation structure.
    const isCurrent = node.href === currentUrl;
    const isAncestor = !isCurrent && node.children && navContainsCurrent(node, currentUrl);
    const cls = isAncestor ? ' class="docs-nav-ancestor"' : "";
    return `<li><a href="${node.href}"${cls}${isCurrent ? ' aria-current="page"' : ""}>${escapeHtml(node.title)}</a></li>`;
  }
  const open = navContainsCurrent(node, currentUrl);
  return `<li><details class="docs-nav-group"${open ? " open" : ""}><summary>${escapeHtml(node.title)}</summary><ul>${node.children.map(child => renderNavNode(child, currentUrl)).join("")}</ul></details></li>`;
}

function leftNav(currentUrl) {
  const items = NAV_TREE.map(node => renderNavNode(node, currentUrl)).join("");
  return `<!-- docs-left-nav:start -->
<aside class="docs-left-nav" id="docs-left-nav" aria-label="Documentation navigation">
  <nav aria-label="Documentation"><ul>${items}</ul></nav>
</aside>
<!-- docs-left-nav:end -->`;
}

function rightToc(html, entry) {
  if (entry.status === "archived" || entry.status === "site-utility") return "";
  const article = html.match(/<article\b[^>]*>([\s\S]*?)<\/article>/i)?.[1] || "";
  const headings = [];
  for (const match of article.matchAll(/<h2\b[^>]*id=["']([^"']+)["'][^>]*>([\s\S]*?)<\/h2>/gi)) {
    const title = stripHtml(match[2]);
    if (title && !headings.some(item => item.id === match[1])) headings.push({id: match[1], title});
  }
  if (headings.length < 3) return "";
  const items = headings.slice(0, 16).map(item => `<li><a href="#${escapeHtml(item.id)}">${escapeHtml(item.title)}</a></li>`).join("");
  // Rendered open by default (desktop wants it permanently expanded, and native
  // <details> content sizing does not reliably survive a CSS-only "force open
  // regardless of the attribute" override). Narrower breakpoints show the summary
  // toggle and readers can collapse it themselves via the normal native behavior.
  return `<!-- docs-toc:start --><details class="docs-right-toc" open><summary>On this page</summary><nav aria-label="On this page"><ol>${items}</ol></nav></details><!-- docs-toc:end -->`;
}

function docsFooter() {
  return `<!-- docs-footer:start -->
<div class="docs-footer">
  <p class="docs-footer__copyright">&copy; 2026 Jason Achkar Diab</p>
  <ul class="docs-footer__links">
    <li><a href="/about/quality-methodology/">Evidence methodology</a></li>
    <li><a href="/about/site-provenance/">Site provenance</a></li>
    <li><a href="https://github.com/jasonachkar/cybersecurity-writeups">GitHub</a></li>
  </ul>
  <details class="docs-footer__detail">
    <summary>Publication details</summary>
    <ul>
      <li><strong>Publication target:</strong> gh-pages</li>
      <li><strong>Publication review:</strong> <a href="https://github.com/jasonachkar/cybersecurity-writeups/pull/5">PR #5</a></li>
      <li><strong>Reviewed branch:</strong> <a href="https://github.com/jasonachkar/cybersecurity-writeups/tree/codex/validated-gh-pages-deployment">codex/validated-gh-pages-deployment</a></li>
      <li><strong>Content review date:</strong> ${REVIEW_DATE}</li>
    </ul>
  </details>
</div>
<!-- docs-footer:end -->`;
}

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
  const cardHtml = cards.map(([title, href, copy, status]) => `<a class="docs-card" href="${href}"><span class="docs-card__chip">${escapeHtml(status)}</span><h3 class="docs-card__title">${escapeHtml(title)}</h3><p class="docs-card__desc">${escapeHtml(copy)}</p><span class="docs-card__cta">Open investigation <span aria-hidden="true">&rarr;</span></span></a>`).join("");
  return `<section class="portfolio-hero">
  <p class="portfolio-hero__kicker">Evidence-first security engineering</p>
  <h1 id="security-engineering-decisions-you-can-audit">Security engineering decisions you can audit.</h1>
  <p class="portfolio-hero__lede">Threat models, enforcement points, negative tests and residual risk across cloud identity, application security, delivery pipelines, Kubernetes, detection and software supply chains—without turning a local test into a production claim.</p>
  <div class="portfolio-actions"><a class="portfolio-button portfolio-button--primary" href="#featured-engineering">Review engineering work</a><a class="portfolio-button" href="/docs/research-audit/content-inventory/">Inspect the evidence registry</a></div>
  <p class="docs-provenance-line">Published from <code>gh-pages</code> · reviewed <time datetime="${REVIEW_TIMESTAMP}">${formatLongDate(REVIEW_DATE)}</time> · <a href="/about/site-provenance/">Site provenance</a></p>
</section>
<section aria-labelledby="featured-engineering"><h2 id="featured-engineering">Featured engineering</h2><p>Each page leads with what was checked, what was executed, what remains untested, and when it must be reviewed again.</p><div class="docs-card-grid">${cardHtml}</div></section>
<section aria-labelledby="validated-labs"><h2 id="validated-labs">Runnable labs</h2><p>Repository labs exercise bounded decisions; their status blocks distinguish local models and structural checks from native platform or cryptographic integration.</p><ul class="docs-link-list"><li><a href="/labs/secure-cicd/">Secure CI/CD gate and workflow fixtures</a></li><li><a href="/labs/iam-oidc/">IAM and workload-identity decision cases</a></li><li><a href="/labs/oauth-oidc/">OAuth/OIDC token-boundary cases</a></li><li><a href="/labs/ai-agent-security/">AI external tool-broker cases</a></li><li><a href="/labs/postgresql-rls/">PostgreSQL row-level security</a></li><li><a href="/labs/kubernetes-security/">Kubernetes policy and image-decision fixtures</a></li><li><a href="/labs/supply-chain/">Offline provenance and SBOM policy</a></li><li><a href="/labs/iac-policy/">Terraform plan and Rego fixtures</a></li><li><a href="/labs/azure-landing-zone/">Azure landing-zone Bicep boundary</a></li></ul></section>
<section aria-labelledby="evidence-methodology"><h2 id="evidence-methodology">Evidence and methodology</h2><p>How claims are classified, checked, and rechecked across the site.</p><ul class="docs-link-list"><li><a href="/docs/research-audit/content-inventory/">Evidence registry</a></li><li><a href="/about/quality-methodology/">Quality methodology</a></li><li><a href="/about/site-provenance/">Site provenance</a></li></ul></section>
<section aria-labelledby="study-notes"><h2 id="study-notes">Study paths</h2><p>Certification collections are visibly separated from implementation evidence and tied to their official owner material.</p><ul class="docs-link-list"><li><a href="/docs/certification-notes/az-900/">Microsoft AZ-900</a></li><li><a href="/docs/certification-notes/sc-500/">Microsoft SC-500</a></li><li><a href="/docs/certification-notes/security-plus/">CompTIA Security+ SY0-701</a></li><li><a href="/docs/certification-notes/google-cybersecurity/">Google Cybersecurity Certificate</a></li></ul></section>`;
}

function provenanceBody() {
  return `<h1 id="site-provenance">Site provenance</h1>
<p>This static site is published from the <code>gh-pages</code> branch. Content in this review was examined through <a href="https://github.com/jasonachkar/cybersecurity-writeups/pull/5">PR #5</a> on branch <code>codex/validated-gh-pages-deployment</code>. Runtime validation evidence is available through the associated GitHub Actions workflow runs and uploaded artifacts. Static files do not claim to identify their own final containing commit. GitHub Pages deployment status is tracked separately through GitHub deployment records.</p>
<table><thead><tr><th scope="col">Field</th><th scope="col">Value</th></tr></thead><tbody>
<tr><th scope="row">Canonical site</th><td><a href="${SITE_ORIGIN}">${SITE_ORIGIN}</a></td></tr>
<tr><th scope="row">Repository</th><td><a href="https://github.com/jasonachkar/cybersecurity-writeups">jasonachkar/cybersecurity-writeups</a></td></tr>
<tr><th scope="row">Artifact</th><td>Static GitHub Pages site</td></tr>
<tr><th scope="row">Publication target</th><td><code>gh-pages</code></td></tr>
<tr><th scope="row">Publication review</th><td><a href="https://github.com/jasonachkar/cybersecurity-writeups/pull/5">PR #5</a></td></tr>
<tr><th scope="row">Reviewed branch</th><td><a href="https://github.com/jasonachkar/cybersecurity-writeups/tree/codex/validated-gh-pages-deployment"><code>codex/validated-gh-pages-deployment</code></a></td></tr>
<tr><th scope="row">Content review date</th><td><time datetime="${REVIEW_TIMESTAMP}">July 24, 2026</time></td></tr>
</tbody></table>
<h2 id="integrity-boundary">Integrity boundary</h2>
<p><code>CNAME</code> and <code>.nojekyll</code> remain part of the publication artifact. Generated runtime QA JSON reports are not committed into the deployable tree; Actions artifacts identify the checked-out revision with fields such as <code>sourceCommit</code>, <code>sourceTree</code>, workflow run identifiers, and tool versions. The machine-readable review context is <a href="/site-meta.json"><code>site-meta.json</code></a>.</p>
<h2 id="what-build-evidence-means">What this evidence means</h2>
<p>Repository validation establishes the checked properties recorded by <code>npm run verify:all</code> and the quality workflow. It does not establish cloud deployment, customer use, production availability, or complete security. Each maintained page states its narrower evidence and residual limitations.</p>`;
}

function notFoundBody() {
  return `<h1 id="page-not-found">Page not found</h1>
<p>The address may have changed, the page may have been archived, or the URL may contain a typo.</p>
<ul class="portfolio-actions-list">
  <li><a class="portfolio-button portfolio-button--primary" href="/">Go to the homepage</a></li>
  <li><a class="portfolio-button" href="/#validated-labs">Browse engineering investigations and labs</a></li>
  <li><a class="portfolio-button" href="/docs/research-audit/content-inventory/">Inspect the evidence registry</a></li>
</ul>
<p>Use the site search control in the header to look for a topic by keyword.</p>`;
}

function qualityBody() {
  return `<h1 id="evidence-and-quality-methodology">Evidence and quality methodology</h1><p>The portfolio treats security guidance as an engineering artifact. Status is visible on the page, represented in <a href="/content-status.json"><code>content-status.json</code></a>, and used to drive navigation, search and sitemap inclusion.</p><h2 id="evidence-statuses">Evidence statuses</h2><dl><dt>Verified engineering investigation</dt><dd>Material current-state claims were checked against named primary sources. Examples can still be only partly tested.</dd><dt>Partially verified engineering investigation</dt><dd>Primary-source review covers a bounded area while one or more platform or implementation boundaries remain untested.</dd><dt>Validated lab</dt><dd>The documented positive and negative behavior executed in the stated environment.</dd><dt>Partially tested lab</dt><dd>Only structural, offline, schema or pedagogical-model behavior executed.</dd><dt>Conceptual reference</dt><dd>Architecture or method without end-to-end runtime validation.</dd><dt>Study notes</dt><dd>Owner-aligned learning material, never implementation evidence.</dd><dt>Site utility</dt><dd>Navigational or error pages such as the 404 response; not security guidance and excluded from search and sitemap.</dd><dt>Archived</dt><dd>URL retained for continuity but excluded from normal discovery and unsafe as current guidance.</dd></dl><h2 id="source-hierarchy">Source hierarchy</h2><ol><li>Standards bodies and final specifications.</li><li>Platform-owner documentation and source repositories.</li><li>Incident-owner disclosures, court or regulator records.</li><li>Secondary analysis only when primary material cannot answer the question, labelled accordingly.</li></ol><h2 id="validation-approach">Validation approach</h2><p>The authoritative local command is <code>npm run verify:all</code>. It covers static site checks, JavaScript labs, Go modules, Terraform, OPA, Bicep, policy schemas, PostgreSQL RLS, ShellCheck, PowerShell parse, accessibility, external links, and secret scanning. CI splits the same suites across jobs and uploads provenance-stamped reports as Actions artifacts. Missing external tools fail closed rather than being silently skipped.</p><h2 id="review-intervals">Review intervals</h2><p>Most engineering investigations use a 90-day interval. Rapidly evolving agent/MCP work and publication metadata use 30 days. Certification notes are rechecked against the owner material; a displayed review date is not proof of correctness. Site-utility pages are excluded from normal content-review cadence pressure.</p><h2 id="limitations">Limitations</h2><p>Automated accessibility and structural checks find important classes of defects but do not replace keyboard, assistive-technology, threat-model, platform or human editorial review. A passing finite suite proves only its declared cases.</p>`;
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

function normalizePage(file, html, entry) {
  html = stripGenerated(html);

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
    .replace(/<link\b[^>]*rel=["'](?:prev|next)["'][^>]*>\s*/gi, "");

  // Replaced in place when present (rather than stripped-then-reinserted) so a stray
  // line ending from the surrounding template can't get displaced by one line and
  // flip-flop between runs.
  const customCss = html.match(/<link\b[^>]*href=["']([^"']*css\/custom\.css)["'][^>]*>/i);
  if (!customCss) throw new Error(`${file}: custom stylesheet link not found`);
  const portfolioHref = customCss[1].replace(/custom\.css$/, "portfolio.css");
  const portfolioTag = `<link rel="stylesheet" href="${portfolioHref}">`;
  const portfolioLinkRe = /<link\b[^>]*href=["'][^"']*css\/portfolio\.css["'][^>]*>/i;
  html = portfolioLinkRe.test(html)
    ? html.replace(portfolioLinkRe, portfolioTag)
    : html.replace(customCss[0], `${customCss[0]}\n${portfolioTag}`);

  const bundleScript = html.match(/<script\b[^>]*src=["']([^"']*assets\/javascripts\/bundle[^"']+)["'][^>]*>\s*<\/script>/i);
  if (bundleScript) {
    const jsDir = bundleScript[1].replace(/assets\/javascripts\/bundle[^"']+$/, "assets/javascripts/");
    let injected = bundleScript[0];
    if (!html.includes("portfolio-a11y.js")) injected += `\n<script src="${jsDir}portfolio-a11y.js" defer></script>`;
    if (!html.includes("docs-ui.js")) injected += `\n<script src="${jsDir}docs-ui.js" defer></script>`;
    if (injected !== bundleScript[0]) html = html.replace(bundleScript[0], injected);
  }

  html = removeDivByClass(html, "md-sidebar--primary");
  html = removeDivByClass(html, "md-sidebar--secondary");

  // One compact header: Material's shadow modifier is replaced by a single bottom
  // border in CSS, the visible product title is shortened, and the GitHub link gets
  // an explicit accessible name now that its long repository text is visually hidden.
  html = html.replace('class="md-header md-header--shadow"', 'class="md-header"');
  // Scoped to the header element only: one archived page's title happens to contain
  // this exact phrase, and a document-wide replace would rewrite it (and its derived
  // id slug) a little further on every run — the header brand text is all this should touch.
  html = html.replace(/<header\b[^>]*>[\s\S]*?<\/header>/i,
    headerMatch => headerMatch.replaceAll("Cloud Security Engineering", "Security Engineering Docs"));
  html = html.replace(
    /(<a href="[^"]*" title="Go to repository" class="md-source")(?![^>]*aria-label)/,
    '$1 aria-label="GitHub repository: jasonachkar/cybersecurity-writeups"'
  );
  // Make search visually prominent (icon + label) with an explicit accessible name;
  // the visible text is aria-hidden since the label itself already carries the name.
  html = html.replace(
    /(<label class="md-header__button md-icon" for="__search">)([\s\S]*?)(<\/label>)/,
    (_, open, inner, close) => `${open.replace('for="__search">', 'for="__search" aria-label="Search documentation">')}${inner}<span class="docs-search-label" aria-hidden="true">Search documentation</span>${close}`
  );

  html = html.replace(/<meta\b[^>]*name=["']author["'][^>]*>/i, '<meta name="author" content="Jason Achkar Diab">');
  if (!/<meta\b[^>]*name=["']author["']/i.test(html)) html = html.replace(/<\/head>/i, '  <meta name="author" content="Jason Achkar Diab">\n</head>');

  // Replaced in place (rather than stripped-then-reinserted) so repeated runs never
  // leave orphaned leading whitespace from the previous tag behind.
  const canonicalPath = entry.replacement || pageUrl(file);
  const canonical = `${SITE_ORIGIN}${canonicalPath === "/" ? "/" : canonicalPath}`;
  const robots = entry.indexable ? "index, follow" : (entry.replacement ? "noindex, follow" : "noindex, nofollow");
  const canonicalTag = `<link rel="canonical" href="${canonical}">`;
  html = /<link\b[^>]*rel=["']canonical["'][^>]*>/i.test(html)
    ? html.replace(/<link\b[^>]*rel=["']canonical["'][^>]*>/i, canonicalTag)
    : html.replace(/<\/head>/i, `  ${canonicalTag}\n</head>`);
  const robotsTag = `<meta name="robots" content="${robots}">`;
  html = /<meta\b[^>]*name=["']robots["'][^>]*>/i.test(html)
    ? html.replace(/<meta\b[^>]*name=["']robots["'][^>]*>/i, robotsTag)
    : html.replace(/<\/head>/i, `  ${robotsTag}\n</head>`);

  const title = h1Title(html);
  html = html.replace(/<title>[\s\S]*?<\/title>/i, `<title>${escapeHtml(title)} | Jason Achkar Diab</title>`);

  html = html.replace(/<div class="md-copyright">[\s\S]*?<div class="md-copyright__highlight site-provenance"[\s\S]*?<\/div>\s*<\/div>/i,
    '<div class="md-copyright">&copy; 2026 Jason Achkar Diab. Security guidance is scoped by page-level evidence.</div>');
  html = html.replace(/<footer\b([^>]*)>/i, `<footer$1>\n${docsFooter()}`);

  const currentUrl = pageUrl(file);
  if (entry.status !== "site-utility") {
    const crumbs = breadcrumbs(currentUrl);
    const evidence = evidenceSummary(entry);
    html = html.replace(/<h1\b[^>]*>[\s\S]*?<\/h1>/i, match => `${crumbs ? `${crumbs}\n` : ""}${match}\n${evidence}`);

    const currency = CERTIFICATION_CURRENCY.find(([prefix]) => file.startsWith(prefix));
    if (currency && entry.status === "study-notes") {
      const banner = `<aside class="study-currency" aria-label="Official-owner check"><strong>Official-owner check</strong><p>${currency[1]}</p></aside>`;
      html = html.replace("<!-- docs-evidence:end -->", `<!-- docs-evidence:end -->\n${banner}`);
    }

    const toc = rightToc(html, entry);
    html = wrapDivByClass(html, "md-content", leftNav(currentUrl), toc);

    const nav = prevNext(currentUrl);
    if (nav) html = insertBeforeArticleClose(html, nav);
  } else {
    html = wrapDivByClass(html, "md-content", leftNav(currentUrl), "");
  }

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

// Pages whose <article> body this script fully regenerates on every run (via
// replaceArticle) are exempt from the content-preservation fingerprint below —
// there is no hand-authored prose there to protect.
const GENERATOR_OWNED_PATHS = new Set([
  "index.html",
  "404.html",
  "about/site-provenance/index.html",
  qualityPath,
  "docs/research-audit/content-inventory/index.html",
  "docs/certification-notes/security-plus/index.html"
]);

function articleProse(html) {
  return stripHtml(stripGenerated(html).match(/<article\b[^>]*>([\s\S]*?)<\/article>/i)?.[1] || "");
}

for (const record of records.values()) {
  const originalHtml = read(record.file);
  const isArchived = record.entry.status === "archived" || (!record.entry.indexable && record.entry.status !== "site-utility");
  const isGeneratorOwned = GENERATOR_OWNED_PATHS.has(record.file) || isArchived;
  const beforeProse = isGeneratorOwned ? null : articleProse(originalHtml);

  let html = originalHtml;
  if (record.file === "index.html") html = replaceArticle(html, homeBody());
  else if (record.file === "404.html") html = replaceArticle(html, notFoundBody());
  else if (record.file === "about/site-provenance/index.html") html = replaceArticle(html, provenanceBody());
  else if (record.file === qualityPath) html = replaceArticle(html, qualityBody());
  else if (record.file === "docs/research-audit/content-inventory/index.html") html = replaceArticle(html, registryBody(records));
  else if (record.file === "docs/certification-notes/security-plus/index.html") html = replaceArticle(html, securityPlusBody());
  else if (isArchived) html = replaceArticle(html, archiveBody(record.entry));

  html = normalizePage(record.file, html, record.entry);

  if (!isGeneratorOwned) {
    const afterProse = articleProse(html);
    if (afterProse !== beforeProse) {
      throw new Error(`${record.file}: article prose changed during maintenance (content-preservation check failed)`);
    }
  }

  write(record.file, html);
  record.title = h1Title(html);
}

const manifest = {};
for (const [file, record] of records) {
  manifest[pageUrl(file)] = {
    title: record.title,
    status: record.entry.status,
    indexable: Boolean(record.entry.indexable),
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
  publicationReview: "PR #5",
  reviewBranch: "codex/validated-gh-pages-deployment",
  pullRequest: 5,
  artifactType: "static GitHub Pages site",
  contentReviewTimestamp: REVIEW_TIMESTAMP,
  contentReviewDate: "July 24, 2026",
  evidenceModel: "page-level status and validation disclosures",
  runtimeEvidence: "GitHub Actions artifacts for the checked-out revision",
  note: "Static files do not claim to identify their own final containing commit."
};
write("site-meta.json", `${JSON.stringify(siteMeta, null, 2)}\n`);

const indexableCount = [...records.values()].filter(item => item.entry.indexable).length;
console.log(`Maintained ${records.size} HTML pages: ${indexableCount} indexable, ${records.size - indexableCount} archived.`);
console.log(`Generated ${Object.keys(manifest).length} status records, ${searchDocs.length} search records, and ${sitemapUrls.length} sitemap URLs.`);
