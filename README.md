# Cloud Security Engineering Research and Labs

Evidence-driven write-ups, threat models, tested controls, and reproducible labs
covering cloud identity, secure delivery pipelines, software supply chains,
multi-tenant systems, Kubernetes, detection engineering, application security, and
AI agent security.

[![Content quality](https://github.com/jasonachkar/cybersecurity-writeups/actions/workflows/content-quality.yml/badge.svg)](https://github.com/jasonachkar/cybersecurity-writeups/actions/workflows/content-quality.yml)
[![Deployment freshness](https://github.com/jasonachkar/cybersecurity-writeups/actions/workflows/site-freshness.yml/badge.svg)](https://github.com/jasonachkar/cybersecurity-writeups/actions/workflows/site-freshness.yml)

The repository distinguishes sourced engineering guidance from executable evidence.
A polished diagram is not treated as proof that a control works, and a passing
structural test is not described as production experience.

## Evidence labels

| Label | Meaning |
| --- | --- |
| **Validated Lab** | Runnable positive and negative fixtures checked by repository automation |
| **Engineering Investigation** | Threat model, enforcement design, evidence, limitations, and operational trade-offs |
| **Conceptual Reference** | Primary-source synthesis or illustrative design without an end-to-end runtime test |
| **Study Notes** | Certification-oriented material; not equivalent to engineering implementation evidence |

Article front matter records source quality, implementation status, reviewed
standards or platform documentation, and a technical-review interval. See the
[metadata contract](docs/METADATA.md),
[authoring guide](docs/AUTHORING_GUIDE.md), and
[security-content contribution standard](docs/CONTRIBUTING_SECURITY_CONTENT.md).

## Featured engineering investigations

### Secure CI/CD trust boundaries

[Secure CI/CD Pipeline Architecture and Trust Boundaries](devsecops/secure-cicd-pipeline-design.md)
separates untrusted pull-request execution, trusted builds, and privileged release.
The companion [CI/CD lab](labs/secure-cicd/README.md) includes deliberately unsafe
`pull_request_target` handling, protected workflow fixtures, fail-closed security
gates, and negative tests.

**Evidence status:** tested policy and fixture behavior; no live deployment is
performed.

### Multi-tenant SaaS isolation

[Engineering Tenant Isolation for a Multi-tenant SaaS Platform](appsec/saas-multitenancy-isolation.md)
models authorization across API, database, cache, storage, messaging, and telemetry
boundaries. The [PostgreSQL RLS lab](labs/postgresql-rls/README.md) tests
transaction-scoped tenant context, cross-tenant reads and writes, tenant-key
mutation, missing context, role attributes, forced RLS for the table owner, policy
drift, and connection reuse.

**Evidence status:** PostgreSQL integration lab; application pool and non-database
boundaries remain explicitly scoped limitations.

### SecureObs architecture

[SecureObs: Customer-side CI Security Scanning with a Multi-tenant Findings Platform](devsecops/secureobs-multitenant-security-scanner.md)
documents a sanitized trust model for customer-side scanning, normalized finding
ingestion, tenant authorization, artifact trust, build-gate integrity, and abuse
resistance.

**Evidence status:** owner-confirmed architecture plus repository pattern labs.
Unverified implementation details are labeled as recommendations, not current
facts.

## Validated labs

| Lab | Security property exercised | Native tooling |
| --- | --- | --- |
| [IAM and workload federation](labs/iam-oidc/README.md) | Issuer/audience/subject trust, boundaries, `PassRole`, external ID | Dependency-free policy evaluator |
| [Secure CI/CD](labs/secure-cicd/README.md) | Untrusted workflow isolation and fail-closed gates | Node.js |
| [Supply-chain evidence](labs/supply-chain/README.md) | Digest, provenance identity, builder/source policy, tamper rejection | Node.js |
| [PostgreSQL RLS](labs/postgresql-rls/README.md) | Transaction tenant context and cross-tenant denial | PostgreSQL 18.4 container |
| [Terraform and Rego](labs/iac-policy/README.md) | Backend hardening and positive/negative plan policy | Terraform 1.14.6, OPA 1.17.0 |
| [Kubernetes and Kyverno](labs/kubernetes-security/README.md) | Pod baseline, image identity, network policy | Kyverno CLI 1.18.2 |
| [OAuth and OIDC](labs/oauth-oidc/README.md) | Token validation, key rotation, PKCE, exact redirects | Node.js 24.12.0, Go 1.26.1 |
| [AI tool broker](labs/ai-agent-security/README.md) | External authorization, approval binding, replay and kill switch | Node.js |
| [Azure landing zone](labs/azure-landing-zone/README.md) | Parser-valid Bicep and federated deployment boundary | Azure CLI/Bicep |

Each lab states what its tests do **not** prove. Native external tools are pinned in
CI; local validation reports missing-tool limitations instead of inventing results.

## Architecture and threat-model research

- [AWS IAM federation and delegation](cloud-security/iam-at-scale.md)
- [Kubernetes multi-tenancy boundaries](cloud-security/kubernetes-multi-tenancy.md)
- [OAuth 2.0 and OpenID Connect security](appsec/oauth2-oidc-deep-dive.md)
- [Infrastructure as Code policy engineering](devsecops/iac-security-and-policy-as-code.md)
- [Software supply-chain evidence](devsecops/supply-chain-sbom-signing.md)
- [AI agent authorization and tool security](appsec/ai-agent-security.md)
- [Cloud incident case studies](threat-intel/cloud-breach-case-studies.md)

The [complete content inventory](docs/research-audit/content-inventory.md) records the
review state, evidence links, factual-risk signals, and next action for every
authored page. The
[strong-claim queue](docs/research-audit/strong-claim-review.md) makes absolute or
security-significant wording observable for human review.

## Tutorials

Tutorials are implementation-oriented learning material. Their metadata indicates
whether commands were tested, partially tested, or remain illustrative.

- [Azure landing-zone security](docs/tutorials/azure-landing-zone/README.md)
- [OWASP API Security Top 10](docs/tutorials/owasp-api-security-top-10/README.md)
- [Detection engineering with Microsoft Sentinel](docs/tutorials/detection-engineering-sentinel/README.md)
- [CI/CD security gates](docs/tutorials/ci-cd-gates/README.md)
- [Securing Microsoft Entra ID](docs/tutorials/securing-entra-id/README.md)

## Study notes

Certification notes are retained as **Study Notes** and are not presented as
validated production engineering:

- [CompTIA Security+](docs/certification-notes/security-plus/README.md)
- [Microsoft AZ-900](docs/certification-notes/az-900/README.md)
- [Google Cybersecurity Certificate](docs/certification-notes/google-cybersecurity/README.md)
- [Microsoft SC-500](docs/certification-notes/sc-500/README.md)

Exam objectives change. Verify each outline against the certification owner's
current official study guide before using these notes for preparation.

## Repository validation

Install locked dependencies and run the content, code, policy, and lab gate:

```text
npm ci --ignore-scripts
npm run validate
```

The gate covers Markdown, YAML and JSON parsing, metadata, generated indexes,
repository links, strong-claim reporting, action pinning, JavaScript and Go
compilation, Terraform formatting and validation, reproducible fixture bytes,
runnable JavaScript lab tests, and native policy tests. OPA, Kyverno, Go,
Terraform, and ShellCheck are mandatory in CI; local runs report a limitation when
an optional tool is unavailable.

Run the disposable database integration separately:

```text
npm run rls:test
```

The documentation job installs `requirements-docs.txt`, builds MkDocs with
`--strict --clean`, and validates provenance, CNAME, canonical URLs, sitemap
coverage, stale-file removal, and source footers before publication. With the
documentation virtual environment installed, the same build-only check is:

```text
./scripts/deploy-docs.sh
```

The publication workflow generates `gh-pages` only from a validated push to
`main`. After that workflow succeeds, the public output exposes its full source SHA
and UTC build timestamp through `site-meta.json` and the Build Provenance page. The
scheduled freshness check fails visibly if the public source SHA differs from
`main`.

## Scope and integrity

- Content is educational and defensive.
- Examples use placeholders and do not deploy paid cloud resources during
  validation.
- The repository does not claim customer use, employer outcomes, penetration-test
  findings, or production operation unless evidence is explicitly available.
- `verified` means material claims were reviewed against named evidence; it does not
  mean a design eliminates every attack path.
- Responsible disclosure and platform terms still apply to any independent
  testing.

Contributions should follow
[CONTRIBUTING_SECURITY_CONTENT.md](docs/CONTRIBUTING_SECURITY_CONTENT.md) and the
[research policy](docs/RESEARCH_POLICY.md).

<!-- AUTOGENERATED_INDEX_START -->
## 📚 Index

_This section is autogenerated. Do not edit entries here directly; update each writeup’s front matter instead._

### ☁️ Cloud Security

- [AWS IAM at Scale: Federation, Delegation, and Guardrails](cloud-security/iam-at-scale.md) —  · 2026-07-21 · 30 min
- [Kubernetes Multi-tenancy: Boundaries, Isolation, and Operations](cloud-security/kubernetes-multi-tenancy.md) —  · 2026-07-21 · 31 min
- [AWS Multi-Account Landing Zones: Guardrails and Control-Plane Isolation](cloud-security/multi-account-landing-zones.md) —  · 2026-06-01 · 16 min
- [Cloud Detection and Response: Designing Resilient SIEM Pipelines, CloudTrail Auditing, and Automated Response](cloud-security/cloud-detection-and-response.md) — Detection Engineering, CloudTrail, Incident Response, SIEM (+1) · 2026-06 · 18 min
- [Cloud Network Segmentation: VPC Architecture, Transit Gateway Routing, and PrivateLink Integration](cloud-security/cloud-network-segmentation.md) — VPC, Transit Gateway, PrivateLink, Network Security (+1) · 2026-06 · 18 min
- [Serverless Security: Function-Level IAM, Ephemeral Lifecycles, and Runtime Isolation](cloud-security/serverless-security.md) — Serverless, AWS Lambda, API Gateway, IAM (+1) · 2026-06 · 16 min

### 💻 Application Security

- [Threat-Driven Security Architecture for AI Agents](appsec/ai-agent-security.md) —  · 2026-07-23 · 38 min
- [Engineering Tenant Isolation for a Multi-tenant SaaS Platform](appsec/saas-multitenancy-isolation.md) —  · 2026-07-21 · 32 min
- [OAuth 2.0 and OpenID Connect Security Engineering](appsec/oauth2-oidc-deep-dive.md) —  · 2026-07-21 · 28 min
- [API and Microservices Threat Modeling: STRIDE, Trust Boundaries, and Header Propagation Security](appsec/api-microservices-threat-modeling.md) — API Security, Threat Modeling, STRIDE, Microservices (+1) · 2026-06 · 16 min
- [Runtime Application Protection: Comparing WAF and RASP Architectures, eBPF Filtering, and Evasion Mitigation](appsec/runtime-protection-rasp-waf.md) — WAF, RASP, eBPF, Runtime Security (+1) · 2026-06 · 16 min

### 🛡️ DevSecOps

- [Infrastructure as Code Security and Policy Engineering](devsecops/iac-security-and-policy-as-code.md) —  · 2026-07-21 · 29 min
- [Secure CI/CD Pipeline Architecture and Trust Boundaries](devsecops/secure-cicd-pipeline-design.md) —  · 2026-07-21 · 32 min
- [SecureObs: Customer-side CI Security Scanning with a Multi-tenant Findings Platform](devsecops/secureobs-multitenant-security-scanner.md) —  · 2026-07-21 · 28 min
- [Software Supply-chain Evidence: SBOMs, Provenance, Signing, and Verification](devsecops/supply-chain-sbom-signing.md) —  · 2026-07-21 · 32 min
- [Enterprise Secrets Management: HashiCorp Vault, Dynamic Provisioning, and Memory Protection](devsecops/secrets-management.md) — Secrets Management, HashiCorp Vault, Cloud Security, Encryption (+1) · 2026-06 · 18 min

### 🕵️ Threat Intelligence

- [Cloud Incident Case Studies: Evidence, Chronology, and Control Lessons](threat-intel/cloud-breach-case-studies.md) —  · 2026-07-21 · 25 min
- [Cloud and Kubernetes Attack Paths: Preconditions, Enforcement Points, and Broken Links](threat-intel/attack-path-analysis.md) —  · 2026-06-01 · 18 min

### 📘 Tutorials

- [Azure Landing Zone Security Engineering Guide](docs/tutorials/azure-landing-zone/README.md) —  · 2026-07-21 · 35 min
- [Configuring Azure Firewall with UDR-Based Traffic Control](docs/tutorials/azure-firewall-walkthrough/README.md) — Security, Azure · 2026-06 · 8 min
- [Detection Engineering with Microsoft Sentinel](docs/tutorials/detection-engineering-sentinel/README.md) — Security, Sentinel · 2026-06 · 17 min
- [OWASP API Security Top 10 (2023)](docs/tutorials/owasp-api-security-top-10/README.md) — Security, OWASP · 2026-06 · 28 min
- [Implementing Security Gates in CI/CD Pipelines](docs/tutorials/ci-cd-gates/README.md) — DevSecOps, CI/CD, SAST, SCA (+4) · 2024-06 · 25 min
- [Securing Azure Entra ID: A Zero Trust Approach](docs/tutorials/securing-entra-id/README.md) — Azure, Entra ID, IAM, Zero Trust (+3) · 2024-05 · 25 min

### 🔬 Research

- [Advanced Cloud Security Engineering: IAM, DevSecOps, Architecture & Detection](docs/research/enterprise-cloud-security-engineering/README.md) — Cloud Security, IAM, DevSecOps, Detection Engineering (+4) · 2026-06 · 55 min
- [Common OAuth 2.0 Misconfigurations and Exploits](docs/research/oauth-misconfigurations/README.md) — Security, OAuth · 2026-06 · 13 min
- [Threat Modeling for Multi-Tenant SaaS Applications](docs/research/threat-modeling-saas/README.md) — Security, SaaS · 2026-06 · 22 min

### 🎓 Certification Notes

- [CompTIA Security+ SY0-701 Study Guide](docs/certification-notes/security-plus/README.md) — Security, CompTIA · 2026-06 · 17 min
- [Google Cybersecurity Certificate Study Guide](docs/certification-notes/google-cybersecurity/README.md) — Linux, SQL, Python, SIEM (+1) · 2026-06 · 20 min
- [Microsoft AZ-900: Azure Fundamentals Study Guide](docs/certification-notes/az-900/README.md) — Azure, Cloud Security, Fundamentals · 2026-06 · 15 min
- [Microsoft SC-500 Study Notes: End-to-End Security Controls for Cloud and AI Workloads](docs/certification-notes/sc-500/README.md) —  · 2026-06-01 · 8 min
<!-- AUTOGENERATED_INDEX_END -->
