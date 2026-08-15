# Security scripts, packages, and small utilities

This section contains the security scripts, packages, and small command-line tools I have written while researching cloud security, application security, DevSecOps, and threat intelligence. Not everything here is a standalone command-line program — some are Go packages meant to be imported or exercised through their own tests rather than run directly. Each category page shows the source directly on the page, along with what it does, what access it needs, how I tested it, and where its limitations are.

<section>

## Cloud Security

[Open the Cloud Security category](/scripts/cloud-security/)

- [Kubernetes RBAC privilege-escalation auditor](/scripts/cloud-security/#k8s-rbac-auditor) <span class="docs-script-meta">Go · Read-only · Go test suite (48 cases)</span>

</section>

<section>

## Application Security

[Open the Application Security category](/scripts/application-security/)

- [OAuth PKCE (S256) verifier and generator](/scripts/application-security/#oauth-pkce-verifier) <span class="docs-script-meta">Go · Read-only · Go test suite</span>

</section>

<section>

## DevSecOps

[Open the DevSecOps category](/scripts/devsecops/)

- [Kyverno policy schema validator](/scripts/devsecops/#kyverno-policy-schema-check) <span class="docs-script-meta">Python · Read-only · Runs in CI against the pinned Kyverno v1.18.2 CRD</span>
- [Tetragon policy schema validator](/scripts/devsecops/#tetragon-policy-schema-check) <span class="docs-script-meta">Python · Read-only · Runs in CI against the pinned Tetragon v1.7.0 CRD</span>

</section>

<section>

## Threat Intelligence

[Open the Threat Intelligence category](/scripts/threat-intelligence/)

- [CloudTrail suspicious-activity analyzer](/scripts/threat-intelligence/#cloudtrail-analyzer) <span class="docs-script-meta">Go · Read-only · Go test suite (9 cases)</span>

</section>
