export const SITE_ORIGIN = "https://docs.jasonachkardiab.com";
export const REVIEW_DATE = "2026-07-24";
export const REVIEW_TIMESTAMP = "2026-07-24T11:48:39Z";

export const STATUS_LABELS = {
  verified: "Verified engineering investigation",
  "partially-verified": "Partially verified engineering investigation",
  "validated-lab": "Validated lab",
  "partially-tested": "Partially tested lab",
  conceptual: "Conceptual reference",
  "study-notes": "Study Notes — not implementation evidence",
  archived: "Archived / requires technical review",
  "site-utility": "Site utility page"
};

const entries = new Map();

function add(path, data) {
  entries.set(path, {
    indexable: true,
    reviewIntervalDays: 90,
    evidence: [],
    limitations: [],
    sources: [],
    runnableEvidence: "None",
    proves: "The page states its own bounded evidence.",
    notProves: "No production deployment or complete security boundary is implied.",
    tags: [],
    ...data
  });
}

add("index.html", {
  status: "conceptual",
  evidence: ["Curated entry points map to page-level evidence disclosures."],
  limitations: ["The landing page summarizes evidence; each investigation defines its own trust and test boundaries."],
  sources: ["Page-level references and content-status.json"],
  runnableEvidence: "Linked lab suites",
  proves: "Which work is maintained and how evidence is classified.",
  notProves: "That every described control ran in a production environment.",
  tags: ["security engineering", "portfolio", "evidence"]
});

add("404.html", {
  status: "site-utility",
  indexable: false,
  reviewIntervalDays: 365,
  evidence: [],
  limitations: ["Utility missing-page response; not security guidance."],
  sources: [],
  runnableEvidence: "None",
  proves: "Visitors receive a navigable missing-page response.",
  notProves: "Nothing about prior content existence.",
  tags: ["site utility"]
});

add("about/site-provenance/index.html", {
  status: "conceptual",
  reviewIntervalDays: 30,
  evidence: [
    "Publication target gh-pages, publication review PR #5, reviewed branch, domain, and content review date are stated without a self-referential commit claim.",
    "Runtime QA evidence is produced as GitHub Actions artifacts for the checked-out revision, not committed JSON reports."
  ],
  limitations: [
    "Static validation does not establish cloud deployment, production availability, or customer use.",
    "GitHub Pages deployment status is tracked separately through GitHub deployment records."
  ],
  sources: ["Repository branch and PR metadata", "GitHub Actions workflow runs"],
  runnableEvidence: "npm run verify:all / .github/workflows/gh-pages-quality.yml",
  proves: "The artifact's review and publication context.",
  notProves: "That static files identify their own final containing commit, or that cloud deployment succeeded."
});

add("about/quality-methodology/index.html", {
  status: "conceptual",
  evidence: ["Defines source hierarchy, validation semantics, review intervals, and archive behavior."],
  limitations: ["Automated checks support but do not replace expert review."],
  sources: ["Repository evidence policy", "Primary-source references on maintained pages"],
  runnableEvidence: "npm run verify:all",
  proves: "How portfolio claims are classified and rechecked.",
  notProves: "That a finite validation suite establishes complete security."
});

add("docs/research-audit/content-inventory/index.html", {
  status: "conceptual",
  reviewIntervalDays: 30,
  evidence: ["Curated explicit metadata; no keyword-derived topic inference."],
  limitations: ["The registry summarizes page disclosures and must be read with the linked investigation."],
  sources: ["content-status.json", "Linked primary-source reference sections"],
  runnableEvidence: "npm run verify:all",
  proves: "Discovery, evidence status, runnable artifacts, and next review date.",
  notProves: "Unlisted implementation, production operation, or control completeness.",
  tags: ["evidence registry", "content status"]
});

const engineering = {
  "devsecops/secure-cicd-pipeline-design/index.html": {
    evidence: ["Trust boundaries and fail-closed gate fixtures are documented and locally exercised."],
    limitations: ["The fixture does not deploy; attestation verification depends on GitHub's service and expected signer workflow."],
    sources: ["GitHub Actions security hardening", "GitHub artifact attestations", "SLSA 1.2"],
    runnableEvidence: "labs/secure-cicd/tests/run-tests.js",
    proves: "Untrusted validation is separated from trusted build and release identities.",
    notProves: "That a production repository has these protections enabled."
  },
  "appsec/saas-multitenancy-isolation/index.html": {
    label: "Partially tested engineering investigation",
    evidence: ["PostgreSQL RLS boundary cases, role attributes, and pooled-client session lifecycle are exercised in a disposable database lab."],
    limitations: ["API authorization, queues, caches, object storage, and telemetry boundaries are not exercised by the database lab."],
    sources: ["PostgreSQL row security documentation", "OWASP Authorization Cheat Sheet"],
    runnableEvidence: "labs/postgresql-rls",
    proves: "Specified database policies reject tested cross-tenant operations.",
    notProves: "End-to-end tenant isolation across every application and infrastructure boundary."
  },
  "appsec/ai-agent-security/index.html": {
    reviewIntervalDays: 30,
    evidence: [
      "Local broker fixtures cover authorized low-impact calls, missing/expired/mismatched approvals, sequential and concurrent replay, kill-switch, and unknown-argument denial.",
      "ApprovalStore.consumeIfUnused enforces one successful consumption under concurrent tests via an in-memory compare-and-set that models a durable conditional write."
    ],
    limitations: [
      "In-memory ApprovalStore is a teaching model, not a distributed durable store.",
      "No production identity validation, MCP enforcement, network sandboxing, or real payment execution is proven.",
      "No model provider or production agent runtime is exercised."
    ],
    sources: ["MCP specification 2025-11-25", "OWASP agentic security guidance", "NIST AI RMF"],
    runnableEvidence: "labs/ai-agent-security/tests/broker.test.js",
    proves: "The local broker rejects the tested unauthorized requests; approvals are action-bound; concurrent local consumption succeeds once.",
    notProves: "Distributed durability, MCP enforcement, network sandboxing, real payments, or that prompts/content filters form an authorization boundary."
  },
  "cloud-security/iam-at-scale/index.html": {
    evidence: ["Federation, delegation, PassRole, external-ID, and boundary decisions have runnable local policy cases."],
    limitations: ["The evaluator is not AWS IAM's production authorization engine and no cloud resources are deployed."],
    sources: ["AWS IAM User Guide", "AWS STS documentation", "GitHub OIDC guidance"],
    runnableEvidence: "labs/iam-oidc/tests/run-tests.js",
    proves: "The repository's explicit trust-policy cases accept and deny the intended fixtures.",
    notProves: "The effective permissions of an untested AWS organization."
  },
  "appsec/oauth2-oidc-deep-dive/index.html": {
    evidence: ["Issuer, audience, time, nonce, state, PKCE, redirect, and key-rotation cases have local fixtures."],
    limitations: ["No commercial identity provider conformance suite or production authorization server is exercised."],
    sources: ["RFC 9700", "OpenID Connect Core", "RFC 7636", "OpenID FAPI 2.0"],
    runnableEvidence: "labs/oauth-oidc/tests/oauth-security.test.js",
    proves: "The local boundary adapter rejects the enumerated malformed or misbound inputs.",
    notProves: "Universal OAuth/OIDC interoperability or provider conformance."
  },
  "cloud-security/kubernetes-multi-tenancy/index.html": {
    evidence: ["Pod, network-policy, and image-decision fixtures exercise positive and negative cases."],
    limitations: ["Image signature, certificate, registry, transparency, and live admission verification were not executed end to end."],
    sources: ["Kubernetes multi-tenancy and NetworkPolicy documentation", "Kyverno 1.18 policy documentation"],
    runnableEvidence: "labs/kubernetes-security/tests/run-tests.js",
    proves: "The local decision model and structural fixtures implement their stated finite cases.",
    notProves: "Live cluster isolation or native Sigstore verification."
  },
  "devsecops/iac-security-and-policy-as-code/index.html": {
    evidence: ["Terraform plan fixtures cover secure, insecure, unknown, and deleted-control states."],
    limitations: ["No cloud deployment is authorized; provider-side behavior is not exercised."],
    sources: ["Terraform JSON plan format", "OPA policy testing", "NIST SSDF"],
    runnableEvidence: "labs/iac-policy/tests/run-tests.js",
    proves: "The repository policy handles its declared plan fixtures and failure states.",
    notProves: "That every provider plan or runtime drift is detected."
  },
  "devsecops/supply-chain-sbom-signing/index.html": {
    label: "Partially tested engineering investigation",
    evidence: ["Artifact digest, SBOM linkage, provenance fields, and verifier-adapter contract have offline tests."],
    limitations: ["No production DSSE envelope, certificate chain, Rekor/transparency, or cryptographic signature verification is executed."],
    sources: ["SLSA 1.2", "in-toto Attestation Framework", "CycloneDX"],
    runnableEvidence: "labs/supply-chain/tests/run-tests.js",
    proves: "The offline policy rejects enumerated identity, source, builder, and digest mismatches.",
    notProves: "Cryptographic signer identity or transparency-log inclusion."
  },
  "devsecops/secureobs-multitenant-security-scanner/index.html": {
    evidence: ["Owner-confirmed architecture is separated from repository-reproduced patterns and recommendations."],
    limitations: ["Sanitized design does not disclose proprietary detail or claim customer use, uptime, compliance, or complete isolation."],
    sources: ["Owner-confirmed statements", "Linked repository lab patterns", "NIST SSDF"],
    runnableEvidence: "Linked repository pattern labs",
    proves: "Which security patterns are reproduced in this public repository.",
    notProves: "Undisclosed product implementation or production outcomes."
  },
  "threat-intel/cloud-breach-case-studies/index.html": {
    evidence: ["Chronologies distinguish incident-owner disclosure from inference and control lessons."],
    limitations: ["Public reporting cannot establish undisclosed facts or complete root cause."],
    sources: ["Incident-owner disclosures", "Regulator or court records where cited"],
    runnableEvidence: "None — documented incident analysis",
    proves: "What cited public evidence supports and where uncertainty remains.",
    notProves: "Unpublished incident detail or control effectiveness in another environment."
  },
  "appsec/api-microservices-threat-modeling/index.html": {
    evidence: ["Workload identity, end-user context, token audience, direct-service bypass, and authorization failure cases are explicitly modeled."],
    limitations: ["No service mesh, token service, or production resource server is deployed."],
    sources: ["NIST SP 800-204 series", "RFC 9700", "RFC 8693", "OpenID Connect Core", "Kubernetes documentation"],
    runnableEvidence: "Documented negative-test matrix",
    proves: "The required identities, claims, and enforcement points for two bounded propagation patterns.",
    notProves: "That an internal network or mTLS alone authorizes a business operation."
  },
  "appsec/runtime-protection-rasp-waf/index.html": {
    evidence: [
      "WAF, in-process, and eBPF controls are compared by enforcement point, context, bypass, and failure behavior.",
      "The TracingPolicyNamespaced manifest was validated against the pinned Tetragon v1.7.0 CRD structural schema in this review."
    ],
    limitations: ["No live cluster enforcement test was run; the Tetragon example is schema-validated only."],
    sources: ["Cilium Tetragon documentation and pinned CRD", "OWASP WAF guidance"],
    runnableEvidence: "scripts/validate-tetragon-policy.py against the pinned v1.7.0 CRD",
    proves: "The narrow scope and failure modes of layered runtime controls.",
    notProves: "That shell denial prevents all RCE or that runtime controls replace authorization and patching."
  },
  "cloud-security/cloud-detection-and-response/index.html": {
    label: "Partially verified — schema reviewed; no live Sentinel execution",
    evidence: ["Sentinel KQL columns are mapped to the documented AWSCloudTrail schema and response controls are bounded."],
    limitations: ["No live Sentinel workspace executed the query; data delivery and connector health remain environment-specific."],
    sources: ["Microsoft AWSCloudTrail table schema", "AWS CloudTrail", "Amazon S3 Object Lock"],
    runnableEvidence: "KQL/schema review only",
    proves: "The query uses documented columns and the response design includes safety controls.",
    notProves: "Detection performance, ingestion health, or safe containment in a live tenant."
  },
  "cloud-security/cloud-network-segmentation/index.html": {
    evidence: ["Routing, endpoint-policy, centralized/distributed egress, IPv6, DNS, and inspection failure modes are explicitly separated."],
    limitations: ["Illustrative network configurations are not applied to AWS accounts."],
    sources: ["AWS Transit Gateway", "AWS PrivateLink", "Amazon S3 gateway and interface endpoint documentation"],
    runnableEvidence: "Terraform validation only where a complete example is present",
    proves: "Which routing and policy layers must cooperate for the described designs.",
    notProves: "That a subnet, Transit Gateway, DNS filter, or endpoint alone provides complete isolation."
  },
  "cloud-security/multi-account-landing-zones/index.html": {
    evidence: ["Organization, account-vending, guardrail, identity, logging, and recovery boundaries are primary-source reviewed."],
    limitations: ["No AWS organization or Control Tower landing zone is deployed."],
    sources: ["AWS Organizations", "AWS Control Tower", "AWS IAM Identity Center"],
    runnableEvidence: "Architecture and policy investigation",
    proves: "The decision and failure model documented by the page.",
    notProves: "Effective controls in an uninspected AWS organization."
  },
  "cloud-security/serverless-security/index.html": {
    evidence: ["Event identity, authorizers, Lambda integration, execution reuse, IAM roles, secrets, networking, and WAF decisions are separated."],
    limitations: ["No Lambda function, API Gateway, VPC path, or WAF policy is deployed."],
    sources: ["AWS Lambda security and execution environment", "API Gateway Lambda proxy and private integration", "API Gateway API keys"],
    runnableEvidence: "Illustrative configurations only",
    proves: "The trust and permission decisions required for the documented serverless paths.",
    notProves: "That VPC attachment, a WAF, or one-role-per-function is universally required."
  },
  "devsecops/secrets-management/index.html": {
    evidence: ["Identity, delivery, rotation, runtime exposure, revocation, and failure semantics are threat-modelled separately."],
    limitations: ["No Vault cluster, Secrets Store CSI provider, or production rotation workflow is executed."],
    sources: ["Kubernetes Secrets", "Secrets Store CSI Driver", "HashiCorp Vault dynamic secrets"],
    runnableEvidence: "Illustrative configurations with explicit boundaries",
    proves: "Which component retrieves a secret and what exposure or availability risk remains.",
    notProves: "That dynamic or memory-backed delivery eliminates compromise."
  },
  "threat-intel/attack-path-analysis/index.html": {
    evidence: ["Three scenarios enumerate foothold, preconditions, edges, evidence, break points, negative tests, and residual risk."],
    limitations: ["Graph reachability is not asserted as exploitability; live tenant graph data is not ingested."],
    sources: ["MITRE ATT&CK where behavior matches", "AWS, Kubernetes, and authorization platform documentation"],
    runnableEvidence: "Documented scenario negative-test matrices",
    proves: "How an evidenced edge can be broken or monitored in each scenario.",
    notProves: "That the modeled attack path exists in a specific environment."
  }
};

for (const [path, data] of Object.entries(engineering)) {
  add(path, {status: "partially-verified", tags: ["engineering investigation"], ...data});
}

const labs = {
  "labs/secure-cicd/index.html": {
    status: "validated-lab",
    evidence: ["Positive, negative, malformed, scanner-failure, and secret-result fixtures run through the fail-closed gate."],
    limitations: ["No release or cloud deployment occurs; GitHub-hosted attestation verification is a separate external boundary."],
    sources: ["GitHub Actions", "GitHub artifact attestations"],
    runnableEvidence: "node labs/secure-cicd/tests/run-tests.js",
    proves: "The local gate and workflow fixtures handle the enumerated trust-boundary cases.",
    notProves: "Repository rules, protected environments, or live attestations in another repository."
  },
  "labs/iam-oidc/index.html": {
    status: "validated-lab",
    evidence: ["Issuer, audience, subject, environment, external-ID, permission-boundary, and PassRole cases execute locally."],
    limitations: ["The evaluator is intentionally smaller than AWS or Azure production authorization engines."],
    sources: ["AWS IAM and STS", "Microsoft Entra workload identity federation"],
    runnableEvidence: "node labs/iam-oidc/tests/run-tests.js",
    proves: "The declared local policies accept and reject the fixture matrix.",
    notProves: "Effective cloud permissions outside the fixtures."
  },
  "labs/oauth-oidc/index.html": {
    status: "validated-lab",
    evidence: ["Token, redirect, PKCE, state, nonce, time, audience, issuer, and key-rotation tests execute locally."],
    limitations: ["No provider conformance suite or browser authorization flow is run."],
    sources: ["RFC 9700", "OpenID Connect Core", "RFC 7636"],
    runnableEvidence: "node --test labs/oauth-oidc/tests/oauth-security.test.js",
    proves: "The bounded adapter rejects the enumerated invalid inputs.",
    notProves: "Authorization-server or client conformance."
  },
  "labs/ai-agent-security/index.html": {
    status: "validated-lab",
    reviewIntervalDays: 30,
    evidence: [
      "Broker fixtures include concurrent replay: exactly one executor invocation and APPROVAL_REPLAYED for the loser.",
      "Action-bound approval, expiry, kill-switch, and unknown-argument cases execute locally."
    ],
    limitations: [
      "In-memory atomic consumption models a durable CAS; it does not prove Redis/PostgreSQL/DynamoDB durability.",
      "No model provider, MCP server, or real payment path is integrated."
    ],
    sources: ["MCP 2025-11-25", "NIST AI RMF"],
    runnableEvidence: "node --test labs/ai-agent-security/tests/broker.test.js",
    proves: "The local broker denies the enumerated unauthorized calls and consumes a high-impact approval only once under concurrent tests.",
    notProves: "Distributed durability, prompt safety, MCP enforcement, or production agent isolation."
  },
  "labs/iac-policy/index.html": {
    status: "partially-tested",
    evidence: [
      "Plan-decision fixtures cover secure, insecure, unknown, and deleted-control cases.",
      "CI runs Terraform 1.14.6 fmt/init/validate and OPA 1.17.0 native Rego tests against the published fixtures."
    ],
    limitations: ["No cloud plan is applied; provider-side behavior is not exercised."],
    sources: ["Terraform plan JSON", "OPA"],
    runnableEvidence: "npm run verify:terraform; npm run verify:opa; node labs/iac-policy/tests/run-tests.js",
    proves: "The local harness and pinned native tools cover their declared fixtures.",
    notProves: "Provider runtime behavior or complete policy coverage."
  },
  "labs/kubernetes-security/index.html": {
    status: "partially-tested",
    evidence: [
      "Local pod, network, and image-decision cases include accepted and denied inputs.",
      "Native Kyverno CLI 1.18.2 tests exercise the hardened-pod policy.",
      "The ImageValidatingPolicy manifest was validated against the pinned Kyverno v1.18.2 CRD structural schema in this review."
    ],
    limitations: [
      "Image-signature policy remains schema/offline only; signature, certificate, registry, transparency, digest resolution, and live admission are not executed end to end."
    ],
    sources: ["Kubernetes", "Kyverno 1.18.2"],
    runnableEvidence: "kyverno test labs/kubernetes-security; node labs/kubernetes-security/tests/run-tests.js; scripts/validate-kyverno-policy.py",
    proves: "The pedagogical decision model and native hardened-pod policy tests handle their finite fixture sets.",
    notProves: "Live admission or cryptographic image verification."
  },
  "labs/supply-chain/index.html": {
    status: "partially-tested",
    evidence: ["Offline digest, builder, source, build-type, and SBOM linkage decisions execute locally."],
    limitations: ["DSSE, signing certificates, transparency, and production cryptographic verification are not performed."],
    sources: ["SLSA 1.2", "in-toto", "CycloneDX"],
    runnableEvidence: "node labs/supply-chain/tests/run-tests.js",
    proves: "The offline policy contract rejects the enumerated mismatches.",
    notProves: "Signer identity, certificate validity, or transparency inclusion."
  },
  "labs/postgresql-rls/index.html": {
    status: "validated-lab",
    evidence: [
      "RLS runtime, boundary, and catalog SQL suites executed against a disposable postgres:18.4-alpine3.24 container in this review.",
      "Pooled-client lifecycle tests (pg 8.22.0) executed physical-session reuse, missing context, error, cancellation, and concurrent-tenant cases."
    ],
    limitations: ["The lab validates database-layer policies only; it is not an application, cache, queue, or object-storage isolation test."],
    sources: ["PostgreSQL row security"],
    runnableEvidence: "labs/postgresql-rls/run-tests.ps1",
    proves: "The documented positive and negative database cases executed in this review.",
    notProves: "Application-layer authorization, cache, queue, or object-storage isolation."
  },
  "labs/azure-landing-zone/index.html": {
    status: "partially-tested",
    evidence: [
      "Bicep and policy artifacts model hierarchy, guardrails, and a federated deployment boundary.",
      "CI compiles labs/azure-landing-zone/main.bicep with Azure CLI Bicep and discards the generated JSON."
    ],
    limitations: ["No Azure authentication or resource deployment occurs."],
    sources: ["Azure landing zone", "Azure Policy", "Bicep"],
    runnableEvidence: "npm run verify:bicep",
    proves: "Only parser and structural compilation behavior recorded by the validation report.",
    notProves: "Effective Azure policy or runtime deployment behavior."
  }
};

for (const [path, data] of Object.entries(labs)) {
  add(path, {tags: ["security lab"], ...data});
}

function addStudy(paths, data) {
  for (const path of paths) {
    add(path, {
      status: "study-notes",
      evidence: [data.currency],
      limitations: ["Study notes summarize an owner-published outline and are not implementation evidence."],
      sources: [data.source],
      runnableEvidence: "None — study material",
      proves: "The maintained study outline and its review date.",
      notProves: "Hands-on implementation, exam coverage beyond the official outline, or a passing score.",
      tags: ["study notes", data.name]
    });
  }
}

addStudy([
  "docs/certification-notes/az-900/index.html",
  "docs/certification-notes/az-900/domain-1-concepts/index.html",
  "docs/certification-notes/az-900/domain-2-architecture-services/index.html",
  "docs/certification-notes/az-900/domain-3-management-governance/index.html"
], {
  name: "AZ-900",
  currency: "Microsoft study guide last updated 2026-06-22; skills measured from 2026-07-20.",
  source: "https://learn.microsoft.com/en-us/credentials/certifications/resources/study-guides/az-900"
});

addStudy([
  "docs/certification-notes/sc-500/index.html",
  "docs/certification-notes/sc-500/domain-1-identity/index.html",
  "docs/certification-notes/sc-500/domain-2-storage-networking/index.html",
  "docs/certification-notes/sc-500/domain-3-secure-compute/index.html",
  "docs/certification-notes/sc-500/domain-4-manage-monitor-posture/index.html"
], {
  name: "SC-500",
  currency: "Microsoft study guide last updated 2026-05-13; current four-domain grouping checked 2026-07-24.",
  source: "https://learn.microsoft.com/en-us/credentials/certifications/resources/study-guides/sc-500"
});

addStudy(["docs/certification-notes/google-cybersecurity/index.html"], {
  name: "Google Cybersecurity Certificate",
  currency: "Google's official curriculum was checked 2026-07-23; Google does not publish a dated exam study guide for this course certificate.",
  source: "https://grow.google/certificates/cybersecurity/"
});

addStudy(["docs/certification-notes/security-plus/index.html"], {
  name: "Security+ SY0-701",
  currency: "CompTIA's official Security+ page and SY0-701 objectives were checked 2026-07-23; no page-level update date is invented.",
  source: "https://www.comptia.org/en-us/certifications/security/"
});

export const CERTIFICATION_CURRENCY = [
  ["docs/certification-notes/az-900/", "Microsoft study guide last updated <strong>2026-06-22</strong>; skills measured from <strong>2026-07-20</strong>. <a href=\"https://learn.microsoft.com/en-us/credentials/certifications/resources/study-guides/az-900\">Official AZ-900 study guide</a>."],
  ["docs/certification-notes/sc-500/", "Microsoft study guide last updated <strong>2026-05-13</strong>. The maintained collection follows the current four domains. <a href=\"https://learn.microsoft.com/en-us/credentials/certifications/resources/study-guides/sc-500\">Official SC-500 study guide</a>."],
  ["docs/certification-notes/google-cybersecurity/", "Google's official curriculum was checked <strong>2026-07-23</strong>; it does not publish a dated exam blueprint for this course certificate. <a href=\"https://grow.google/certificates/cybersecurity/\">Official curriculum</a>."],
  ["docs/certification-notes/security-plus/", "CompTIA's Security+ page and SY0-701 objectives were checked <strong>2026-07-23</strong>; no unsupported guide-update date is claimed. <a href=\"https://www.comptia.org/en-us/certifications/security/\">Official Security+ page</a>." ]
];

export const REPLACEMENT_PREFIXES = [
  ["docs/research/oauth-misconfigurations/", "/appsec/oauth2-oidc-deep-dive/"],
  ["docs/research/threat-modeling-saas/", "/appsec/saas-multitenancy-isolation/"],
  ["docs/research/devsecops/iac-security-and-policy-as-code/", "/devsecops/iac-security-and-policy-as-code/"],
  ["docs/research/devsecops/secure-cicd-pipelines-and-environments/", "/devsecops/secure-cicd-pipeline-design/"],
  ["docs/research/enterprise-cloud-security-engineering/iam-workload-identity/", "/cloud-security/iam-at-scale/"],
  ["docs/research/enterprise-cloud-security-engineering/kubernetes-multi-tenancy-and-platform-security/", "/cloud-security/kubernetes-multi-tenancy/"],
  ["docs/research/enterprise-cloud-security-engineering/devsecops-pipeline-hardening/", "/devsecops/secure-cicd-pipeline-design/"],
  ["docs/research/enterprise-cloud-security-engineering/multi-account-landing-zones-and-iam/", "/cloud-security/multi-account-landing-zones/"],
  ["docs/certification-notes/sc-500/domain-3-compute-posture/", "/docs/certification-notes/sc-500/domain-3-secure-compute/"],
  ["docs/certification-notes/sc-500/domain-4-ai-security/", "/docs/certification-notes/sc-500/domain-3-secure-compute/"],
  ["docs/certification-notes/security-plus/", "/docs/certification-notes/security-plus/"],
  ["docs/research-audit/strong-claim-review/", "/about/quality-methodology/"],
  ["docs/research-audit/security-content-audit/", "/about/quality-methodology/"],
  ["docs/research-audit/modernization-completion-report/", "/about/quality-methodology/"],
  ["docs/templates/security-writeup-template/", "/about/quality-methodology/"],
  ["docs/AUTHORING_GUIDE/", "/about/quality-methodology/"],
  ["docs/CONTRIBUTING_SECURITY_CONTENT/", "/about/quality-methodology/"],
  ["docs/METADATA/", "/about/quality-methodology/"],
  ["docs/METADATA_MIGRATION/", "/about/quality-methodology/"]
];

REPLACEMENT_PREFIXES.unshift(
  ["docs/research/appsec/api-microservices-oauth-saas-multitenancy/", "/appsec/api-microservices-threat-modeling/"],
  ["docs/research/enterprise-cloud-security-engineering/detection-engineering/", "/cloud-security/cloud-detection-and-response/"],
  ["docs/tutorials/ci-cd-gates/", "/devsecops/secure-cicd-pipeline-design/"],
  ["docs/tutorials/detection-engineering-sentinel/", "/cloud-security/cloud-detection-and-response/"],
  ["docs/tutorials/azure-landing-zone/", "/labs/azure-landing-zone/"],
  ["docs/tutorials/owasp-api-security-top-10/", "/appsec/api-microservices-threat-modeling/"],
  ["docs/standards/security-standards-review/", "/about/quality-methodology/"],
  ["docs/RESEARCH_POLICY/", "/about/quality-methodology/"]
);

export const EXPLICIT_ARCHIVED_PATHS = new Set([
  "docs/AUTHORING_GUIDE/index.html",
  "docs/CONTRIBUTING_SECURITY_CONTENT/index.html",
  "docs/METADATA/index.html",
  "docs/METADATA_MIGRATION/index.html",
  "docs/RESEARCH_POLICY/index.html",
  "docs/certification-notes/sc-500/domain-3-compute-posture/index.html",
  "docs/certification-notes/sc-500/domain-4-ai-security/index.html",
  "docs/certification-notes/security-plus/domain-1-threats/index.html",
  "docs/certification-notes/security-plus/domain-2-architecture/index.html",
  "docs/certification-notes/security-plus/domain-3-operations/index.html",
  "docs/certification-notes/security-plus/labs/lab-iam/index.html",
  "docs/certification-notes/security-plus/labs/lab-network-security/index.html",
  "docs/certification-notes/security-plus/practice-questions/index.html",
  "docs/certification-notes/security-plus/quick-reference/index.html",
  "docs/research-audit/modernization-completion-report/index.html",
  "docs/research-audit/security-content-audit/index.html",
  "docs/research-audit/strong-claim-review/index.html",
  "docs/research/appsec/api-microservices-oauth-saas-multitenancy/index.html",
  "docs/research/devsecops/iac-security-and-policy-as-code/index.html",
  "docs/research/devsecops/secure-cicd-pipelines-and-environments/index.html",
  "docs/research/enterprise-cloud-security-engineering/cloud-security-architecture/index.html",
  "docs/research/enterprise-cloud-security-engineering/detection-engineering/index.html",
  "docs/research/enterprise-cloud-security-engineering/devsecops-pipeline-hardening/index.html",
  "docs/research/enterprise-cloud-security-engineering/iam-workload-identity/index.html",
  "docs/research/enterprise-cloud-security-engineering/index.html",
  "docs/research/enterprise-cloud-security-engineering/kubernetes-multi-tenancy-and-platform-security/index.html",
  "docs/research/enterprise-cloud-security-engineering/multi-account-landing-zones-and-iam/index.html",
  "docs/research/oauth-misconfigurations/attack-scenarios/index.html",
  "docs/research/oauth-misconfigurations/code-examples/index.html",
  "docs/research/oauth-misconfigurations/index.html",
  "docs/research/oauth-misconfigurations/mitigations/index.html",
  "docs/research/threat-modeling-saas/data-flow-diagrams/index.html",
  "docs/research/threat-modeling-saas/index.html",
  "docs/research/threat-modeling-saas/mitigations/index.html",
  "docs/research/threat-modeling-saas/stride-analysis/index.html",
  "docs/research/threat-modeling-saas/templates/index.html",
  "docs/scripts/app-security/index.html",
  "docs/scripts/cloud-security/index.html",
  "docs/scripts/devsecops/index.html",
  "docs/scripts/threat-intel/index.html",
  "docs/standards/security-standards-review/index.html",
  "docs/templates/security-writeup-template/index.html",
  "docs/tutorials/azure-firewall-walkthrough/index.html",
  "docs/tutorials/azure-landing-zone/architecture/index.html",
  "docs/tutorials/azure-landing-zone/iam/index.html",
  "docs/tutorials/azure-landing-zone/implementation-templates/index.html",
  "docs/tutorials/azure-landing-zone/index.html",
  "docs/tutorials/azure-landing-zone/networking/index.html",
  "docs/tutorials/azure-landing-zone/policy-governance/index.html",
  "docs/tutorials/ci-cd-gates/azure-devops/index.html",
  "docs/tutorials/ci-cd-gates/github-actions/index.html",
  "docs/tutorials/ci-cd-gates/index.html",
  "docs/tutorials/ci-cd-gates/tools/index.html",
  "docs/tutorials/detection-engineering-sentinel/detection-templates/index.html",
  "docs/tutorials/detection-engineering-sentinel/index.html",
  "docs/tutorials/owasp-api-security-top-10/code-examples/index.html",
  "docs/tutorials/owasp-api-security-top-10/examples/insecure-example/index.html",
  "docs/tutorials/owasp-api-security-top-10/examples/secure-example/index.html",
  "docs/tutorials/owasp-api-security-top-10/index.html",
  "docs/tutorials/owasp-api-security-top-10/mitigation-node/index.html",
  "docs/tutorials/owasp-api-security-top-10/mitigations-dotnet/index.html",
  "docs/tutorials/owasp-api-security-top-10/vulnerabilities/index.html",
  "docs/tutorials/securing-entra-id/conditional-access-policies/index.html",
  "docs/tutorials/securing-entra-id/identity-protection/index.html",
  "docs/tutorials/securing-entra-id/index.html",
  "docs/tutorials/securing-entra-id/monitoring-alerts/index.html",
  "docs/tutorials/securing-entra-id/pim-configuration/index.html"
]);

export {entries};
