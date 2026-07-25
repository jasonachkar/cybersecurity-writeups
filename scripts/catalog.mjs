// Source of truth for the public "Scripts" section. Every script/tool page
// under /scripts/ is generated from this catalogue by maintain-gh-pages.mjs —
// do not hand-edit the generated HTML.
//
// Categories map 1:1 onto the site's research categories so a visitor moving
// between "Research" and "Scripts" sees the same four groupings.

export const SCRIPT_CATEGORIES = [
  {slug: "cloud-security", title: "Cloud Security"},
  {slug: "application-security", title: "Application Security"},
  {slug: "devsecops", title: "DevSecOps"},
  {slug: "threat-intelligence", title: "Threat Intelligence"}
];

export const SCRIPTS = [
  {
    slug: "k8s-rbac-auditor",
    category: "cloud-security",
    name: "Kubernetes RBAC privilege-escalation auditor",
    language: "Go",
    path: "cloud-security/scripts/k8s-rbac/auditor.go",
    relatedResearch: {title: "Kubernetes isolation", href: "/cloud-security/kubernetes-multi-tenancy/"},
    relatedLab: {title: "Kubernetes security lab", href: "/labs/kubernetes-security/"},
    modifiesState: false,
    testStatus: "Go test suite (48 cases)",
    purpose: "It checks a batch of exported Role/ClusterRole and (Cluster)RoleBinding YAML for the RBAC patterns that lead to privilege escalation: binding scope mismatches (RoleBinding referencing a ClusterRole-only resource), and the special verbs (bind, escalate, impersonate) that let a principal grant itself more than its own role appears to allow.",
    why: "The Kubernetes isolation write-up kept coming back to the same question — does this binding actually grant what it looks like it grants? — so I wrote something that answers that mechanically instead of by eye.",
    how: "It indexes the supplied roles by kind/namespace/name, resolves each binding's roleRef against that index, and evaluates each PolicyRule against a small table of known built-in resource scopes plus the special-verb cases. Unknown or custom resources are never assigned a fabricated scope — they come back unknown rather than guessed.",
    requirements: ["Go 1.22+", "No cluster or kubeconfig access — it never calls the Kubernetes API."],
    permissions: "None. It is a pure function over data structures you provide; it does not read files, make network calls, or need any credentials.",
    inputs: "In-memory RoleLike / BindingLike values (in the shipped tests, built from fixture data). There is no CLI entry point today — it is a package you import or exercise via its test suite, not a standalone binary.",
    outputs: "A []Finding slice describing each risky binding: the role, the binding scope, and a human-readable reason.",
    tested: "The 48 test cases in auditor_test.go cover both roles that should be flagged and roles that should come back clean, across ordinary resources, the special verbs, and unresolved/unknown bindings.",
    limitations: [
      "This is a static heuristic over role/binding objects you hand it, not a full effective-permissions engine.",
      "It does not evaluate SubjectAccessReview, SelfSubjectRulesReview, aggregated ClusterRoles, admission policy, or live API discovery.",
      "It has no CLI or YAML-loading entry point yet — wiring in a real `kubectl get -o yaml` export is on my list, not something this does today."
    ],
    usage: "go test ./cloud-security/scripts/k8s-rbac/..."
  },
  {
    slug: "oauth-pkce-verifier",
    category: "application-security",
    name: "OAuth PKCE (S256) verifier and generator",
    language: "Go",
    path: "appsec/scripts/oauth-pkce/pkce.go",
    relatedResearch: {title: "OAuth 2.0 and OIDC", href: "/appsec/oauth2-oidc-deep-dive/"},
    relatedLab: {title: "OAuth/OIDC lab", href: "/labs/oauth-oidc/"},
    modifiesState: false,
    testStatus: "Go test suite",
    purpose: "A small, dependency-free implementation of RFC 7636's S256 PKCE flow: generating a valid random verifier, deriving its challenge, and validating a verifier against a stored challenge using a constant-time comparison.",
    why: "The OAuth/OIDC write-up needed a real PKCE implementation behind its test cases instead of a description of one, so I wrote the minimal correct version and used it as that reference implementation.",
    how: "GenerateRandomVerifier draws from crypto/rand and formats the result to RFC 7636's unreserved-character alphabet. ComputeChallengeS256 does the SHA-256 + base64url-no-padding derivation. ValidatePKCES256 recomputes the expected challenge from the supplied verifier and compares it to the stored one with crypto/subtle.ConstantTimeCompare, and only accepts the S256 method (deliberately, plain is never accepted).",
    requirements: ["Go 1.22+"],
    permissions: "None — no filesystem, network, or credential access. It deliberately never logs the verifier or challenge values it handles.",
    inputs: "A verifier length (for generation) or a verifier/challenge/method triple (for validation).",
    outputs: "A verifier string, a challenge string, or a boolean validation result.",
    tested: "pkce_test.go exercises the correct round trip plus the negative cases: a wrong verifier, a plain-method downgrade attempt, wrong verifier length, invalid characters, and a malformed stored challenge.",
    limitations: [
      "This checks the PKCE mechanics only — it says nothing about redirect-URI matching, state/nonce handling, or token validation, which live in the OAuth/OIDC lab instead.",
      "No CLI entry point; it is meant to be imported or exercised via its tests."
    ],
    usage: "go test ./appsec/scripts/oauth-pkce/..."
  },
  {
    slug: "cloudtrail-analyzer",
    category: "threat-intelligence",
    name: "CloudTrail suspicious-activity analyzer",
    language: "Go",
    path: "threat-intel/scripts/cloudtrail/analyze.go",
    relatedResearch: {title: "Incident case studies", href: "/threat-intel/cloud-breach-case-studies/"},
    relatedLab: null,
    modifiesState: false,
    testStatus: "Go test suite (9 cases)",
    purpose: "It turns a batch of exported AWS CloudTrail events into a short list of findings worth a human look: console logins without MFA, privilege-escalation chains within a time window, repeated KMS Decrypt denies, and signs of log tampering (StopLogging / DeleteTrail).",
    why: "Reading the incident case studies made it obvious how much of a real investigation is just pattern-spotting across thousands of events, so I wrote a small analyzer that does the first pass of that for CloudTrail.",
    how: "ParseEvents decodes a CloudTrail JSON export into typed events. Analyze runs four independent passes over that list — console-login, privilege-chain, KMS-deny-threshold, and log-tampering — each returning its own Finding records, which the caller merges.",
    requirements: ["Go 1.22+", "A CloudTrail JSON export to analyze — it does not call AWS APIs itself."],
    permissions: "None from the tool itself. Reading the CloudTrail export is on you; treat that export as sensitive data regardless of what this analyzer does with it.",
    inputs: "Raw CloudTrail JSON bytes (a []byte), plus an Options struct for thresholds like the privilege-chain time window and KMS-deny count.",
    outputs: "A []Finding slice: which analysis flagged it, the actor ARN, and a description.",
    tested: "analyze_test.go covers each of the four analyses with both events that should fire a finding and quiet events that should not.",
    limitations: [
      "This flags patterns worth checking, not confirmed compromise — every finding needs a human to correlate it against what was actually authorized.",
      "It only understands the CloudTrail event shape it was built against; it has not been run against a live account's trail.",
      "No CLI entry point yet; exercised via Analyze()/ParseEvents() and its test suite."
    ],
    usage: "go test ./threat-intel/scripts/cloudtrail/..."
  },
  {
    slug: "kyverno-policy-schema-check",
    category: "devsecops",
    name: "Kyverno policy schema validator",
    language: "Python",
    path: "scripts/validate-kyverno-policy.py",
    relatedResearch: {title: "Kubernetes isolation", href: "/cloud-security/kubernetes-multi-tenancy/"},
    relatedLab: {title: "Kubernetes security lab", href: "/labs/kubernetes-security/"},
    modifiesState: false,
    testStatus: "Runs in CI against the pinned Kyverno v1.18.2 CRD",
    purpose: "Checks a Kyverno ImageValidatingPolicy against the pinned Kyverno v1.18.2 CRD's structural schema — a quick way to catch a typo'd field or wrong apiVersion without needing a live cluster.",
    why: "I wanted some confidence the Kubernetes lab's policy YAML was structurally valid against the real CRD before I trusted it enough to keep in the repo, without standing up a cluster just to find out.",
    how: "It loads the CRD and the policy YAML, confirms the policy's apiVersion/kind actually match what the CRD serves, then runs the CRD's openAPIV3Schema through the `jsonschema` library against the policy document.",
    requirements: ["Python 3", "jsonschema", "PyYAML", "A pinned copy of the target CRD's YAML"],
    permissions: "None — it only reads the two local files you pass it. It never touches a cluster.",
    inputs: "Two file paths: the CRD YAML and the policy YAML to check.",
    outputs: "Exits cleanly (no output) on success; raises an AssertionError or a jsonschema.ValidationError with a description of the mismatch on failure.",
    tested: "Runs in CI against the fixtures in labs/kubernetes-security on every change.",
    limitations: [
      "This is schema validation only — it says nothing about signature verification, registry access, transparency-log inclusion, or how the policy behaves under live admission.",
      "It validates structure against one pinned CRD version; a different Kyverno version may accept or reject different fields."
    ],
    usage: "python scripts/validate-kyverno-policy.py <crd.yaml> <policy.yaml>"
  },
  {
    slug: "tetragon-policy-schema-check",
    category: "devsecops",
    name: "Tetragon policy schema validator",
    language: "Python",
    path: "scripts/validate-tetragon-policy.py",
    relatedResearch: {title: "Runtime protection (WAF/RASP/eBPF)", href: "/appsec/runtime-protection-rasp-waf/"},
    relatedLab: null,
    modifiesState: false,
    testStatus: "Runs in CI against the pinned Tetragon v1.7.0 CRD",
    purpose: "The same idea as the Kyverno checker, aimed at Cilium Tetragon's TracingPolicyNamespaced CRD: catch a malformed eBPF tracing policy before it's ever pointed at a real cluster.",
    why: "Same reasoning as the Kyverno checker, applied to the runtime-protection write-up's Tetragon policy instead.",
    how: "Loads the CRD and policy YAML, confirms apiVersion/kind/scope line up with what the CRD declares, then validates the policy against the CRD's openAPIV3Schema with `jsonschema`. Kubernetes CRD structural schemas are a restricted subset of JSON Schema, so this is a faithful offline check.",
    requirements: ["Python 3", "jsonschema", "PyYAML", "A pinned copy of the target CRD's YAML"],
    permissions: "None — reads the two local files only, no cluster access.",
    inputs: "Two file paths: the CRD YAML and the policy YAML to check.",
    outputs: "Exits cleanly on success; raises an assertion or validation error describing the mismatch on failure.",
    tested: "Runs in CI against the published policy in appsec/runtime-protection-rasp-waf on every change.",
    limitations: [
      "Schema validation only — not a live admission or enforcement test, and it says nothing about whether the eBPF program actually behaves as the policy describes at runtime.",
      "Tied to one pinned CRD version."
    ],
    usage: "python scripts/validate-tetragon-policy.py <crd.yaml> <policy.yaml>"
  }
];
