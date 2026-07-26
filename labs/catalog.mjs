// Source of truth for the implementation viewer shown on every lab page.
// maintain-gh-pages.mjs reads these paths directly from the tracked
// repository at build time — nothing here is a copy of the code, only a
// pointer to it. Do not hand-edit the injected <!-- docs-lab-source:start -->
// block in the lab HTML; change this file (or the source it points at) and
// re-run `npm run maintain`.

export const LABS = [
  {
    page: "labs/secure-cicd/index.html",
    slug: "secure-cicd",
    title: "Secure CI/CD",
    sourceFiles: [
      {path: "labs/secure-cicd/gate.js", label: "Gate implementation", language: "javascript", primary: true},
      {path: "labs/secure-cicd/tests/run-tests.js", label: "Fixture tests", language: "javascript"},
      {path: "labs/secure-cicd/tests/policy-tests.js", label: "Policy tests", language: "javascript"}
    ],
    runCommands: ["node labs/secure-cicd/tests/run-tests.js", "node --test labs/secure-cicd/tests/policy-tests.js"],
    safetyNotes: ["Runs entirely against local fixture files; makes no network call and needs no credentials."]
  },
  {
    page: "labs/iam-oidc/index.html",
    slug: "iam-oidc",
    title: "IAM and OIDC",
    sourceFiles: [
      {path: "labs/iam-oidc/evaluator.js", label: "Policy evaluator", language: "javascript", primary: true},
      {path: "labs/iam-oidc/tests/run-tests.js", label: "Fixture tests", language: "javascript"}
    ],
    runCommands: ["node labs/iam-oidc/tests/run-tests.js"],
    safetyNotes: ["Evaluates the JSON trust/permission policies under labs/iam-oidc/policies locally; never calls AWS or Azure."]
  },
  {
    page: "labs/oauth-oidc/index.html",
    slug: "oauth-oidc",
    title: "OAuth and OIDC",
    sourceFiles: [
      {path: "labs/oauth-oidc/oauth-security.js", label: "Boundary adapter", language: "javascript", primary: true},
      {path: "labs/oauth-oidc/tests/oauth-security.test.js", label: "Tests", language: "javascript"}
    ],
    runCommands: ["node --test labs/oauth-oidc/tests/oauth-security.test.js"],
    safetyNotes: ["No browser authorization flow or real identity provider is involved; every case is a local fixture."]
  },
  {
    page: "labs/ai-agent-security/index.html",
    slug: "ai-agent-security",
    title: "AI-agent security",
    sourceFiles: [
      {path: "labs/ai-agent-security/broker.js", label: "Broker implementation", language: "javascript", primary: true},
      {path: "labs/ai-agent-security/tests/broker.test.js", label: "Tests", language: "javascript"}
    ],
    runCommands: ["node --test labs/ai-agent-security/tests/broker.test.js"],
    safetyNotes: ["The broker calls a fake local executor. No model, MCP server, or real payment path is involved."]
  },
  {
    page: "labs/postgresql-rls/index.html",
    slug: "postgresql-rls",
    title: "PostgreSQL RLS",
    sourceFiles: [
      {path: "labs/postgresql-rls/init/001-schema.sql", label: "Schema + RLS policies", language: "sql", primary: true},
      {path: "labs/postgresql-rls/tests/rls-tests.sql", label: "RLS tests", language: "sql"},
      {path: "labs/postgresql-rls/tests/pool-tests.js", label: "Pool lifecycle tests", language: "javascript"}
    ],
    runCommands: ["labs/postgresql-rls/run-tests.sh", "labs/postgresql-rls/run-tests.ps1"],
    safetyNotes: ["Requires Docker: the runner starts a disposable postgres:18.4-alpine3.24 container and removes it afterward."]
  },
  {
    page: "labs/kubernetes-security/index.html",
    slug: "kubernetes-security",
    title: "Kubernetes security",
    sourceFiles: [
      {path: "labs/kubernetes-security/policies/hardened-pods.yaml", label: "Kyverno policy", language: "yaml", primary: true},
      {path: "labs/kubernetes-security/policies/verify-release-images.yaml", label: "Image-verification policy", language: "yaml"},
      {path: "labs/kubernetes-security/tests/run-tests.js", label: "Decision-model tests", language: "javascript"}
    ],
    runCommands: ["kyverno test labs/kubernetes-security", "node labs/kubernetes-security/tests/run-tests.js"],
    safetyNotes: ["The Kyverno policy is exercised with the native `kyverno test` CLI against local fixtures; no live cluster is contacted."]
  },
  {
    page: "labs/supply-chain/index.html",
    slug: "supply-chain",
    title: "Supply-chain policy",
    sourceFiles: [
      {path: "labs/supply-chain/verify-provenance.js", label: "Verifier", language: "javascript", primary: true},
      {path: "labs/supply-chain/policy.json", label: "Policy contract", language: "json"},
      {path: "labs/supply-chain/tests/run-tests.js", label: "Tests", language: "javascript"}
    ],
    runCommands: ["node labs/supply-chain/tests/run-tests.js"],
    safetyNotes: ["Offline only: it never contacts a transparency log, registry, or certificate authority."]
  },
  {
    page: "labs/iac-policy/index.html",
    slug: "iac-policy",
    title: "IaC policy",
    sourceFiles: [
      {path: "labs/iac-policy/policy/terraform.rego", label: "Rego policy", language: "rego", primary: true},
      {path: "labs/iac-policy/policy/secure_fixture_test.rego", label: "Rego tests", language: "rego"},
      {path: "labs/iac-policy/tests/run-tests.js", label: "Harness tests", language: "javascript"}
    ],
    runCommands: ["npm run verify:terraform", "npm run verify:opa", "node labs/iac-policy/tests/run-tests.js"],
    safetyNotes: ["No cloud plan is ever applied; `terraform validate` and `opa test` both run against static fixtures."]
  },
  {
    page: "labs/azure-landing-zone/index.html",
    slug: "azure-landing-zone",
    title: "Azure landing zone",
    sourceFiles: [
      {path: "labs/azure-landing-zone/main.bicep", label: "Landing-zone module", language: "bicep", primary: true},
      {path: "labs/azure-landing-zone/modules/policy-baseline.bicep", label: "Policy baseline", language: "bicep"}
    ],
    runCommands: ["npm run verify:bicep"],
    safetyNotes: ["Compiled with the Bicep CLI only; no Azure authentication or deployment occurs."]
  }
];
