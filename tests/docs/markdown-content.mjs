// Shared by static-output tests and real-browser tests. This function runs in
// the browser against article DOM, including closed details and hidden content.
export function rawMarkdownInArticle(article) {
  const findings = [];
  const walker = document.createTreeWalker(article, NodeFilter.SHOW_TEXT);
  while (walker.nextNode()) {
    const node = walker.currentNode;
    const parent = node.parentElement;
    if (parent.closest("pre, code, script, style, textarea, .mermaid, [data-source-viewer]")) continue;
    // Intentional prose demonstrations must carry a specific explanation.
    const example = parent.closest("[data-markdown-example]");
    if (example?.getAttribute("data-markdown-example").trim()) continue;
    const text = node.textContent;
    const patterns = [
      ["heading", /^\s*#{1,6}\s+\S/m],
      ["link", /!?\[[^\]\n]+\]\([^\)\n]+\)/],
      ["fence", /^\s*(?:`{3,}|~{3,})/m],
      ["table", /^\s*\|.+\|[\t ]*$/m],
      ["emphasis", /\*\*[^*\n]+\*\*/],
    ];
    // Numbered headings, table-cell phase labels and prose dashes after inline
    // code in real list items are valid content, not unparsed Markdown lists.
    if (!parent.closest("h1, h2, h3, h4, h5, h6, td, th, li")) {
      patterns.push(["list", /^\s*(?:[-+*]|\d+[.)])\s+\S/m]);
    }
    for (const [kind, pattern] of patterns) {
      if (pattern.test(text)) findings.push({kind, element: parent.tagName.toLowerCase(), text: text.trim().slice(0, 300)});
    }
  }
  return findings;
}

export const scriptCategories = [
  {title: "Cloud Security", url: "/scripts/cloud-security/", id: "cloud-security"},
  {title: "Application Security", url: "/scripts/application-security/", id: "application-security"},
  {title: "DevSecOps", url: "/scripts/devsecops/", id: "devsecops"},
  {title: "Threat Intelligence", url: "/scripts/threat-intelligence/", id: "threat-intelligence"},
];

export const scriptLinks = [
  ["Kubernetes RBAC privilege-escalation auditor", "/scripts/cloud-security/#k8s-rbac-auditor"],
  ["OAuth PKCE (S256) verifier and generator", "/scripts/application-security/#oauth-pkce-verifier"],
  ["Kyverno policy schema validator", "/scripts/devsecops/#kyverno-policy-schema-check"],
  ["Tetragon policy schema validator", "/scripts/devsecops/#tetragon-policy-schema-check"],
  ["CloudTrail suspicious-activity analyzer", "/scripts/threat-intelligence/#cloudtrail-analyzer"],
];

export const studyNoteRoutes = [
  "/docs/certification-notes/sc-500/domain-3-secure-compute/",
  "/docs/certification-notes/sc-500/domain-4-manage-monitor-posture/",
];

export const studyGuideUrl = "https://learn.microsoft.com/en-us/credentials/certifications/resources/study-guides/sc-500";
