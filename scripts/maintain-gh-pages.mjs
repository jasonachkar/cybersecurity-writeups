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
  entries
} from "./site-config.mjs";
import {SCRIPTS, SCRIPT_CATEGORIES} from "./catalog.mjs";

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
    runnableEvidence: "None - archived reference",
    proves: "Only that the previous URL has an explicit lifecycle state.",
    notProves: "Technical currency, implementation, or security effectiveness.",
    replacement,
    originalTitle: title.replace(/^(?:Archived reference:\s*|Old page:\s*)+/i, "")
  };
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
    // Legacy single-TOC marker (replaced by docs-desktop-toc/docs-inline-toc below),
    // one-time cleanup only — never re-generated.
    .replace(/<!-- docs-toc:start -->[\s\S]*?<!-- docs-toc:end -->/g, "")
    // Inserted as the sibling `after` half of wrapDivByClass(html, "md-content", ...),
    // directly abutting whatever originally followed .md-content's closing </div> —
    // same no-trailing-whitespace reasoning as docs-toc above.
    .replace(/<!-- docs-desktop-toc:start -->[\s\S]*?<!-- docs-desktop-toc:end -->/g, "")
    // Inserted with a leading "\n" straight after the evidence/study-currency anchor,
    // no trailing whitespace of our own (matches docs-evidence above).
    .replace(/\n?<!-- docs-inline-toc:start -->[\s\S]*?<!-- docs-inline-toc:end -->/g, "")
    .replace(/\n?<!-- docs-prevnext:start -->[\s\S]*?<!-- docs-prevnext:end -->\s*/g, "")
    // No trailing \s* here either: what follows in the template (the footer-meta div)
    // is original content, not ours to eat.
    .replace(/\n?<!-- docs-footer:start -->[\s\S]*?<!-- docs-footer:end -->/g, "")
    .replace(/<aside\b[^>]*class=["'][^"']*content-evidence[^"']*["'][^>]*>[\s\S]*?<\/aside>/gi, "")
    // Also inserted with a leading "\n" and no trailing whitespace of its own (see above).
    .replace(/\n?<aside\b[^>]*class=["'][^"']*study-currency[^"']*["'][^>]*>[\s\S]*?<\/aside>/gi, "");
}

function breadcrumbs(currentUrl) {
  const record = NAV_INDEX.get(currentUrl);
  if (!record) return "";
  const items = [`<li><a href="/">Home</a></li>`];
  // Pure navigation groups ("Engineering", "Application Security", and most other
  // groups) have no page of their own to link to; a plain-text, non-clickable
  // crumb for them reads as broken rather than as hierarchy, so they are left out
  // entirely. Ancestors that are also a real page (AZ-900, SC-500) keep a real link.
  for (const ancestor of record.trail) {
    if (!ancestor.href) continue;
    items.push(`<li><a href="${ancestor.href}">${escapeHtml(ancestor.title)}</a></li>`);
  }
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

// Single source of heading data for both TOC presentations: a permanently-visible
// desktop <aside> (outside the article, third grid column) and a native <details>
// disclosure rendered inline in the article for narrower widths, where the desktop
// aside is display:none and there is no third grid column to put it in. Both read
// from the same articleHeadings()/tocItems() so there is only ever one heading list.
function articleHeadings(html) {
  const article = html.match(/<article\b[^>]*>([\s\S]*?)<\/article>/i)?.[1] || "";
  const headings = [];
  for (const match of article.matchAll(/<h2\b[^>]*id=["']([^"']+)["'][^>]*>([\s\S]*?)<\/h2>/gi)) {
    const title = stripHtml(match[2]);
    if (title && !headings.some(item => item.id === match[1])) headings.push({id: match[1], title});
  }
  return headings.slice(0, 16);
}

function needsToc(entry, headings) {
  return entry.status !== "archived" && entry.status !== "site-utility" && headings.length >= 3;
}

// Splits an article into its H2 sections (heading id/title + the section's own text,
// from that heading up to the next one) so the search index can offer one focused,
// short result per section — the same location#anchor + per-section-text shape
// mkdocs-material's own search plugin produces, and the shape its bundled
// search-worker already knows how to group under one page with a "N more on this
// page" expander. Without this, a single blob-per-page index gives every match a
// wall-of-text teaser instead of a short, relevant excerpt.
function articleSections(html) {
  const article = html.match(/<article\b[^>]*>([\s\S]*?)<\/article>/i)?.[1] || "";
  const matches = [...article.matchAll(/<h2\b[^>]*id=["']([^"']+)["'][^>]*>([\s\S]*?)<\/h2>/gi)];
  const sections = [];
  for (let i = 0; i < matches.length; i++) {
    const id = matches[i][1];
    const title = stripHtml(matches[i][2]);
    if (!title) continue;
    const start = matches[i].index + matches[i][0].length;
    const end = i + 1 < matches.length ? matches[i + 1].index : article.length;
    const text = stripHtml(article.slice(start, end));
    if (text) sections.push({id, title, text: text.slice(0, 1200)});
  }
  return sections;
}

// The page-level search teaser needs the actual intro prose, not the breadcrumb
// trail and inline-TOC section list that also live inside <article> before the
// first heading (both would otherwise flatten into the teaser as one run-on line
// of unrelated phrases). Restricting to real <p> tag content before the first H2
// sidesteps both, since neither breadcrumbs (a <nav>/<ol>) nor the TOC
// (<details>/<nav>/<ol>) render as <p> elements.
function articleIntro(html) {
  const article = html.match(/<article\b[^>]*>([\s\S]*?)<\/article>/i)?.[1] || "";
  const firstH2 = article.search(/<h2\b/i);
  const introHtml = firstH2 === -1 ? article : article.slice(0, firstH2);
  const paragraphs = [...introHtml.matchAll(/<p\b[^>]*>([\s\S]*?)<\/p>/gi)]
    .map(match => stripHtml(match[1]))
    .filter(Boolean);
  return paragraphs.join(" ").slice(0, 400);
}

function tocItems(headings) {
  return headings.map(item => `<li><a href="#${escapeHtml(item.id)}">${escapeHtml(item.title)}</a></li>`).join("");
}

function desktopToc(headings) {
  const items = tocItems(headings);
  return `<!-- docs-desktop-toc:start -->
<aside class="docs-right-toc" aria-label="On this page">
  <strong class="docs-right-toc__title">On this page</strong>
  <nav aria-label="On this page">
    <ol>${items}</ol>
  </nav>
</aside>
<!-- docs-desktop-toc:end -->`;
}

function inlineToc(headings) {
  const items = tocItems(headings);
  // The nested <nav> gets its own aria-label distinct from the desktop TOC's
  // ("On this page") — both are always present in the static DOM even though CSS
  // shows only one at a given viewport, and two same-role landmarks sharing one
  // accessible name fails unique-landmark validation. The visible text a reader
  // sees (the <summary>) still reads "On this page" either way.
  return `<!-- docs-inline-toc:start -->
<details class="docs-inline-toc">
  <summary>On this page</summary>
  <nav aria-label="On this page (inline)">
    <ol>${items}</ol>
  </nav>
</details>
<!-- docs-inline-toc:end -->`;
}

function docsFooter() {
  return `<!-- docs-footer:start -->
<div class="docs-footer">
  <p class="docs-footer__copyright">&copy; 2026 Jason Achkar Diab</p>
  <ul class="docs-footer__links">
    <li><a href="/#featured-research">Research</a></li>
    <li><a href="/#validated-labs">Labs</a></li>
    <li><a href="/scripts/">Scripts</a></li>
    <li><a href="/#study-notes">Study notes</a></li>
    <li><a href="/about/">About</a></li>
    <li><a href="https://github.com/jasonachkar/cybersecurity-writeups">GitHub</a></li>
  </ul>
</div>
<!-- docs-footer:end -->`;
}

function homeBody() {
  const cards = [
    ["Secure CI/CD trust boundaries", "/devsecops/secure-cicd-pipeline-design/", "Workflow identity, untrusted validation, protected build and attestation policy."],
    ["Multi-tenant SaaS isolation", "/appsec/saas-multitenancy-isolation/", "Authorization across API, database, pool, cache, queue, storage and telemetry boundaries."],
    ["AI-agent authorization", "/appsec/ai-agent-security/", "External authorization, action-bound approval, concurrent local consumption, and bounded tool execution."],
    ["IAM and workload federation", "/cloud-security/iam-at-scale/", "Issuer, audience, subject, delegation, PassRole and permission-boundary decisions."],
    ["OAuth 2.0 and OIDC", "/appsec/oauth2-oidc-deep-dive/", "Exact redirects, PKCE, state, nonce, token audience, JWKS and resource authorization."],
    ["Kubernetes isolation", "/cloud-security/kubernetes-multi-tenancy/", "Namespace, workload identity, network, admission, image and operational failure boundaries."],
    ["IaC policy engineering", "/devsecops/iac-security-and-policy-as-code/", "Unknown values, deleted controls, plan semantics, policy failure and rollout design."],
    ["Supply-chain evidence", "/devsecops/supply-chain-sbom-signing/", "Artifact bytes, SBOM, provenance, signer, builder, source and policy kept distinct."],
    ["SecureObs architecture", "/devsecops/secureobs-multitenant-security-scanner/", "The parts I actually built and confirmed myself, kept separate from patterns I'm still prototyping."],
    ["Incident case studies", "/threat-intel/cloud-breach-case-studies/", "Public breach disclosures, timelines, what I could and couldn't verify, and what I took from each one."]
  ];
  const cardHtml = cards.map(([title, href, copy]) => `<a class="docs-card" href="${href}"><h3 class="docs-card__title">${escapeHtml(title)}</h3><p class="docs-card__desc">${escapeHtml(copy)}</p><span class="docs-card__cta">Read the write-up <span aria-hidden="true">&rarr;</span></span></a>`).join("");
  const scriptCardHtml = SCRIPT_CATEGORIES.map(category => {
    const scripts = SCRIPTS.filter(script => script.category === category.slug);
    if (!scripts.length) return "";
    return `<a class="docs-card" href="/scripts/${category.slug}/"><h3 class="docs-card__title">${escapeHtml(category.title)}</h3><p class="docs-card__desc">${scripts.length} script${scripts.length === 1 ? "" : "s"}: ${escapeHtml(scripts.map(s => s.name).join("; "))}</p><span class="docs-card__cta">Browse scripts <span aria-hidden="true">&rarr;</span></span></a>`;
  }).join("");
  return `<section class="portfolio-hero">
  <p class="portfolio-hero__kicker">Cybersecurity research by Jason Achkar Diab</p>
  <h1 id="cybersecurity-research-labs-and-scripts">Cybersecurity research, labs, and scripts.</h1>
  <p class="portfolio-hero__lede">This site contains my research notes, technical write-ups, labs, and scripts across cloud security, application security, DevSecOps, and threat intelligence. I document what I studied, what I built, what I tested, and what remains untested.</p>
  <div class="portfolio-actions"><a class="portfolio-button portfolio-button--primary" href="#featured-research">Browse the research</a><a class="portfolio-button" href="#validated-labs">Explore the labs</a><a class="portfolio-button" href="/scripts/">View the scripts</a></div>
  <p class="docs-provenance-line">Last updated <time datetime="${REVIEW_TIMESTAMP}">${formatLongDate(REVIEW_DATE)}</time> · <a href="/about/">About this site</a></p>
</section>
<section aria-labelledby="featured-research"><h2 id="featured-research">Featured research</h2><p>Each write-up says what I tested myself, what's still just a design, and what I'd want to dig into further.</p><div class="docs-card-grid">${cardHtml}</div></section>
<section aria-labelledby="validated-labs"><h2 id="validated-labs">Labs</h2><p>Small, dependency-free labs I wrote to test a specific decision in isolation. They run locally against fakes and fixtures, so they prove the logic holds — not that I've plugged them into a real cloud account or crypto backend yet.</p><ul class="docs-link-list"><li><a href="/labs/secure-cicd/">Secure CI/CD gate and workflow fixtures</a></li><li><a href="/labs/iam-oidc/">IAM and workload-identity decision cases</a></li><li><a href="/labs/oauth-oidc/">OAuth/OIDC token-boundary cases</a></li><li><a href="/labs/ai-agent-security/">AI external tool-broker cases</a></li><li><a href="/labs/postgresql-rls/">PostgreSQL row-level security</a></li><li><a href="/labs/kubernetes-security/">Kubernetes policy and image-decision fixtures</a></li><li><a href="/labs/supply-chain/">Offline provenance and SBOM policy</a></li><li><a href="/labs/iac-policy/">Terraform plan and Rego fixtures</a></li><li><a href="/labs/azure-landing-zone/">Azure landing-zone Bicep boundary</a></li></ul></section>
<section aria-labelledby="featured-scripts"><h2 id="featured-scripts">Scripts</h2><p>Small command-line tools and packages I've written while working on the research above — what they do, what they need, and how I tested them.</p><div class="docs-card-grid">${scriptCardHtml}</div></section>
<section aria-labelledby="study-notes"><h2 id="study-notes">Study notes</h2><p>Certification notes I keep separate from the research above, checked against the official course material.</p><ul class="docs-link-list"><li><a href="/docs/certification-notes/az-900/">Microsoft AZ-900</a></li><li><a href="/docs/certification-notes/sc-500/">Microsoft SC-500</a></li><li><a href="/docs/certification-notes/security-plus/">CompTIA Security+ SY0-701</a></li><li><a href="/docs/certification-notes/google-cybersecurity/">Google Cybersecurity Certificate</a></li></ul></section>`;
}

function aboutBody() {
  return `<h1 id="about-this-site">About this site</h1>
<p>I'm Jason Achkar Diab. This is where I document the cybersecurity research, labs, and scripts I work on outside my day-to-day job: cloud security, application security, DevSecOps, and threat intelligence. I use it to study security architecture, test specific controls in isolation, record what I actually found versus what's still a design, and keep reusable tooling in one place.</p>
<h2 id="how-its-organized">How it's organized</h2>
<dl>
<dt>Research</dt>
<dd>Write-ups on a specific security decision or architecture question. Each one says what I tested myself versus what's still conceptual.</dd>
<dt>Labs</dt>
<dd>Small, dependency-free labs that exercise one decision in isolation, with fixtures for both cases that should pass and cases that should fail.</dd>
<dt>Scripts</dt>
<dd>Standalone command-line tools and packages I've written alongside the research, documented separately from the labs.</dd>
<dt>Study notes</dt>
<dd>My own notes from working through a certification's official material — not a claim that I've implemented everything they describe.</dd>
</dl>
<h2 id="how-i-keep-it-current">How I keep it current</h2>
<p>Before I publish anything, I run a local check (<code>npm run verify:all</code>) that covers the static site, the JavaScript labs, Go modules, Terraform, OPA, Bicep, PostgreSQL RLS, shell/PowerShell scripts, accessibility, and a secrets scan, and GitHub Actions runs the same checks on every change. Passing those checks means the site builds cleanly and the labs run the way I documented — it isn't a claim that everything here has been run against a live deployed environment. I try to revisit most write-ups every 90 days, sooner for fast-moving agent/MCP work.</p>
<h2 id="source">Source</h2>
<p>The source for every page here, including this one, is public: <a href="https://github.com/jasonachkar/cybersecurity-writeups">github.com/jasonachkar/cybersecurity-writeups</a>.</p>`;
}

function notFoundBody() {
  return `<h1 id="page-not-found">Page not found</h1>
<p>The address may have changed, the page may have moved, or the URL may contain a typo.</p>
<ul class="portfolio-actions-list">
  <li><a class="portfolio-button portfolio-button--primary" href="/">Go to the homepage</a></li>
  <li><a class="portfolio-button" href="/#featured-research">Browse the research</a></li>
  <li><a class="portfolio-button" href="/scripts/">Browse the scripts</a></li>
</ul>
<p>Use the site search control in the header to look for a topic by keyword.</p>`;
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
    ? `<p><a class="portfolio-button portfolio-button--primary" href="${entry.replacement}">Go to where this moved</a></p>`
    : `<p><a class="portfolio-button" href="/">Go to the homepage</a></p>`;
  return `<h1 id="archived-reference-${slug(title)}">Old page: ${escapeHtml(title)}</h1><section class="archive-notice" aria-label="Archive notice"><strong>This is an old page, kept online so the link doesn't break.</strong><p>I replaced this content a while back &mdash; it was outdated or overlapped with something I've since written up properly. The URL stays live so nothing pointing here 404s, but treat it as retired.</p>${link}</section><h2 id="archive-behavior">What that means</h2><ul><li>Search engines are told not to index it (<code>noindex</code>).</li><li>It won't turn up in site search or navigation.</li><li>Nothing on it should be read as current.</li></ul>`;
}

function scriptsIndexBody() {
  const cards = SCRIPT_CATEGORIES.map(category => {
    const scripts = SCRIPTS.filter(script => script.category === category.slug);
    const items = scripts.map(script => `<li><a href="/scripts/${script.category}/${script.slug}/">${escapeHtml(script.name)}</a> <span class="docs-script-meta">${escapeHtml(script.language)} &middot; ${script.modifiesState ? "Modifies state" : "Read-only"}</span></li>`).join("");
    return `<section aria-labelledby="scripts-${category.slug}"><h2 id="scripts-${category.slug}">${escapeHtml(category.title)}</h2><p><a href="/scripts/${category.slug}/">Browse the ${escapeHtml(category.title)} category</a></p><ul class="docs-link-list">${items}</ul></section>`;
  }).join("");
  return `<h1 id="security-scripts-and-utilities">Security scripts and utilities</h1><p>This section contains the security scripts and small command-line tools I have written while researching cloud security, application security, DevSecOps, and threat intelligence. Each page explains what the script does, what access it requires, how I tested it, and where its limitations are.</p>${cards}`;
}

function scriptsCategoryBody(category) {
  const scripts = SCRIPTS.filter(script => script.category === category.slug);
  const cards = scripts.map(script => `<a class="docs-card" href="/scripts/${script.category}/${script.slug}/"><h3 class="docs-card__title">${escapeHtml(script.name)}</h3><p class="docs-card__desc">${escapeHtml(script.purpose.split(". ")[0])}.</p><span class="docs-card__cta">${escapeHtml(script.language)} &middot; ${script.modifiesState ? "Modifies state" : "Read-only"}</span></a>`).join("");
  return `<h1 id="${slug(category.title)}-scripts">${escapeHtml(category.title)} scripts</h1><p>The ${escapeHtml(category.title.toLowerCase())} scripts I've written and catalogued here.</p><h2 id="scripts-in-this-category">Scripts</h2><div class="docs-card-grid">${cards}</div>`;
}

function scriptBody(script) {
  const related = [];
  if (script.relatedResearch) related.push(`<li>Related research: <a href="${script.relatedResearch.href}">${escapeHtml(script.relatedResearch.title)}</a></li>`);
  if (script.relatedLab) related.push(`<li>Related lab: <a href="${script.relatedLab.href}">${escapeHtml(script.relatedLab.title)}</a></li>`);
  const relatedHtml = related.length ? `<h2 id="related">Related research</h2><ul>${related.join("")}</ul>` : "";
  return `<h1 id="${slug(script.name)}">${escapeHtml(script.name)}</h1>
<p class="docs-script-badges"><span class="docs-badge">${escapeHtml(script.language)}</span><span class="docs-badge">${script.modifiesState ? "Modifies state" : "Read-only"}</span><span class="docs-badge">${escapeHtml(script.testStatus)}</span></p>
<h2 id="what-it-does">What it does</h2><p>${escapeHtml(script.purpose)}</p>
<h2 id="why-i-wrote-it">Why I wrote it</h2><p>${escapeHtml(script.why)}</p>
<h2 id="how-it-works">How it works</h2><p>${escapeHtml(script.how)}</p>
<h2 id="requirements">Requirements</h2><ul>${script.requirements.map(item => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
<h2 id="permissions-and-safety">Permissions and safety</h2><p>${escapeHtml(script.permissions)}</p>
<h2 id="usage">Usage</h2><pre><code>${escapeHtml(script.usage)}</code></pre>
<h2 id="inputs">Inputs</h2><p>${escapeHtml(script.inputs)}</p>
<h2 id="outputs">Outputs</h2><p>${escapeHtml(script.outputs)}</p>
<h2 id="what-i-tested">What I tested</h2><p>${escapeHtml(script.tested)}</p>
<h2 id="limitations">Limitations</h2><ul>${script.limitations.map(item => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
${relatedHtml}
<h2 id="source-code">Source code</h2><p><a href="https://github.com/jasonachkar/cybersecurity-writeups/blob/gh-pages/${script.path}"><code>${escapeHtml(script.path)}</code></a></p>`;
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
  // Material's inline search box already sits right next to this icon at desktop
  // widths, so it only needs an accessible name here, not a second visible label.
  // One-time cleanup of an earlier run's injected visible label span, which was
  // written in place (not strip/reinject) and so survived past its own removal here.
  html = html.replace(
    /(<label class="md-header__button md-icon" for="__search"(?:\s+aria-label="[^"]*")?>)([\s\S]*?)<span class="docs-search-label" aria-hidden="true">Search documentation<\/span>(<\/label>)/,
    "$1$2$3"
  );
  html = html.replace(
    /<label class="md-header__button md-icon" for="__search">/,
    '<label class="md-header__button md-icon" for="__search" aria-label="Search documentation">'
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

  // Material's own footer-meta copyright block is removed entirely — not merely
  // hidden — so docsFooter() below is the single footer the page ships, not a
  // duplicate stacked on top of Material's original one.
  html = removeDivByClass(html, "md-footer-meta");
  html = html.replace(/<footer\b([^>]*)>/i, `<footer$1>\n${docsFooter()}`);

  const currentUrl = pageUrl(file);
  if (entry.status !== "site-utility") {
    const crumbs = breadcrumbs(currentUrl);
    // Tracks the literal string right after which the next front-matter block should
    // be inserted, so the inline TOC lands after the H1 *and* the study-currency
    // banner (when present) without a second, more fragile regex search for it.
    let afterHeading = null;
    html = html.replace(/<h1\b[^>]*>[\s\S]*?<\/h1>/i, match => {
      afterHeading = match;
      return `${crumbs ? `${crumbs}\n` : ""}${match}`;
    });

    const currency = CERTIFICATION_CURRENCY.find(([prefix]) => file.startsWith(prefix));
    if (currency && entry.status === "study-notes") {
      const banner = `<aside class="study-currency" aria-label="Official-owner check"><strong>Official-owner check</strong><p>${currency[1]}</p></aside>`;
      html = html.replace(afterHeading, `${afterHeading}\n${banner}`);
      afterHeading = banner;
    }

    const headings = articleHeadings(html);
    const includeToc = needsToc(entry, headings);
    if (includeToc) html = html.replace(afterHeading, `${afterHeading}\n${inlineToc(headings)}`);

    html = wrapDivByClass(html, "md-content", leftNav(currentUrl), includeToc ? desktopToc(headings) : "");

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
  "about/index.html",
  "docs/certification-notes/security-plus/index.html",
  "scripts/index.html",
  ...SCRIPT_CATEGORIES.map(category => `scripts/${category.slug}/index.html`),
  ...SCRIPTS.map(script => `scripts/${script.category}/${script.slug}/index.html`)
]);

function articleProse(html) {
  return stripHtml(stripGenerated(html).match(/<article\b[^>]*>([\s\S]*?)<\/article>/i)?.[1] || "");
}

for (const record of records.values()) {
  const originalHtml = read(record.file);
  const isArchived = record.entry.status === "archived" || (!record.entry.indexable && record.entry.status !== "site-utility");
  const isGeneratorOwned = GENERATOR_OWNED_PATHS.has(record.file) || isArchived;
  const beforeProse = isGeneratorOwned ? null : articleProse(originalHtml);

  const scriptEntry = SCRIPTS.find(script => record.file === `scripts/${script.category}/${script.slug}/index.html`);
  const categoryEntry = SCRIPT_CATEGORIES.find(category => record.file === `scripts/${category.slug}/index.html`);

  let html = originalHtml;
  if (record.file === "index.html") html = replaceArticle(html, homeBody());
  else if (record.file === "404.html") html = replaceArticle(html, notFoundBody());
  else if (record.file === "about/index.html") html = replaceArticle(html, aboutBody());
  else if (record.file === "docs/certification-notes/security-plus/index.html") html = replaceArticle(html, securityPlusBody());
  else if (record.file === "scripts/index.html") html = replaceArticle(html, scriptsIndexBody());
  else if (categoryEntry) html = replaceArticle(html, scriptsCategoryBody(categoryEntry));
  else if (scriptEntry) html = replaceArticle(html, scriptBody(scriptEntry));
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
  const location = file === "index.html" ? "" : file.replace(/index\.html$/, "");
  const title = records.get(file).title;
  // A short page-level document (title-boosted, brief teaser) plus one document per
  // H2 section with its own #anchor and just that section's text. Material's search
  // worker groups documents sharing a location by page and shows the page-level one
  // first with any matching sections underneath, matching mkdocs-material's own
  // stock search index shape instead of one 40,000-character blob per page, which
  // made every result a wall of text and gave every match the same one location.
  searchDocs.push({
    location,
    title,
    text: articleIntro(html),
    // Material's search UI renders each string in this array as its own tag chip
    // (and, per lunr, indexes each array entry as its own token) — a joined string
    // like "engineering investigation" was instead getting iterated character by
    // character (strings are iterable in JS), producing one single-letter chip per
    // character instead of one real tag chip.
    tags: entry.tags
  });
  for (const section of articleSections(html)) {
    searchDocs.push({location: `${location}#${section.id}`, title: section.title, text: section.text});
  }
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
  artifactType: "static GitHub Pages site",
  lastUpdated: REVIEW_TIMESTAMP,
  note: "Static files do not claim to identify their own final containing commit; see the repository history for that."
};
write("site-meta.json", `${JSON.stringify(siteMeta, null, 2)}\n`);

const indexableCount = [...records.values()].filter(item => item.entry.indexable).length;
console.log(`Maintained ${records.size} HTML pages: ${indexableCount} indexable, ${records.size - indexableCount} archived.`);
console.log(`Generated ${Object.keys(manifest).length} status records, ${searchDocs.length} search records, and ${sitemapUrls.length} sitemap URLs.`);
