# Research index and evidence coverage

This index distinguishes maintained investigations from historical reference pages.
The 2026-11-02 audit adds an article-specific question, falsifier, threat model,
method, evidence ledger, failure containment and open question to every active
research article listed below. It preserves existing technical explanation.

Source-backed design is T0 here. Static/template checks are T1. Linked local tests
may support T2/T3 for the declared component; paired experiments support T4 only
for their tested corpus. **No complete production architecture was deployed.**
A local-test audit does not complete independent source review; retained articles
remain `requires-review`.

## Maintained research

| Article | Reproducible local boundary | Research question |
| --- | --- | --- |
| [AWS IAM at Scale: Federation, Delegation, and Guardrails](../cloud-security/iam-at-scale.md) | [Lab](../labs/iam-oidc/README.md) | Can subject-bound federation and immutable delegation boundaries separate token acceptance from effective API authority? |
| [Kubernetes Multi-tenancy: Boundaries, Isolation, and Operations](../cloud-security/kubernetes-multi-tenancy.md) | [Lab](../labs/kubernetes-security/README.md) | Which tenant isolation claims are supported by admission fixtures, and which require a real cluster and CNI? |
| [Cloud Network Segmentation and Egress Control: Routing, Private Endpoints and Failure Domains](../cloud-security/cloud-network-segmentation.md) | [Lab](../labs/mcp-tool-ssrf/README.md) | Does a separate gateway prevent a fetch tool from using a direct internal path after URL controls are bypassed? |
| [Cloud Detection Engineering: Durable Telemetry, High-Signal Analytics and Safe Response](../cloud-security/cloud-detection-and-response.md) | [Lab](../labs/cicd-identity-escalation/README.md) | Can a detector preserve the distinction between a failed privilege-change attempt and a reported successful change? |
| [Serverless Security Engineering: Event Trust, Function Identity and Runtime Reuse](../cloud-security/serverless-security.md) | [Lab](../labs/request-lifecycle/README.md) | Can tenant context, event idempotency and secret freshness survive reuse of one handler process? |
| [AWS Multi-Account Landing Zones: Guardrails and Control-Plane Isolation](../cloud-security/multi-account-landing-zones.md) | [Lab](../labs/azure-landing-zone/README.md) | Which hierarchy and audit assumptions can a static landing-zone plan establish before provider-side policy testing? |
| [API and Microservice Trust Boundaries: Workload Identity, User Context and Downstream Authorization](../appsec/api-microservices-threat-modeling.md) | [Lab](../labs/api-bola-multi-tenant/README.md) | Does downstream authorization survive an authenticated direct request, alternate export endpoint and agent wrapper? |
| [OAuth 2.0 and OpenID Connect Security Engineering](../appsec/oauth2-oidc-deep-dive.md) | [Lab](../labs/oauth-oidc/README.md) | Can token authenticity, audience, time, tenant and scope fail independently rather than collapsing into decoded-token acceptance? |
| [Engineering Tenant Isolation for a Multi-tenant SaaS Platform](../appsec/saas-multitenancy-isolation.md) | [Lab](../labs/postgresql-rls/README.md) | Does the database enforce tenant visibility and writes when an application query lacks or reuses tenant context? |
| [Threat-Driven Security Architecture for AI Agents](../appsec/ai-agent-security.md) | [Lab](../labs/ai-agent-security/README.md) | Can a model-proposed action acquire authority without independently bound approval and policy? |
| [Layered Runtime Application Protection: WAF, In-Process Controls and eBPF Enforcement](../appsec/runtime-protection-rasp-waf.md) | [Lab](../labs/mcp-tool-ssrf/README.md) | Does application-level destination enforcement reject the same internal-fetch requests even when edge filtering is absent? |
| [Evidence-Driven AI Agent and MCP Security](../ai-security/evidence-driven-agent-security.md) | [Lab](../labs/ai-agent-security/README.md) | Can an assessment keep configured capability, attempted activity and executed authority distinct? |
| [MCP Tool Authorization Lab: A Gateway That Holds When the Model Does Not](../ai-security/mcp-tool-authorization-lab.md) | [Lab](../labs/mcp-tool-authorization/README.md) | Does a deterministic gateway keep tool authority independent of a compromised model's behaviour, and does every decision leave a verifiable record? |
| [Linux Host Analysis Without Invented Attack Paths](../linux-security/evidence-driven-host-analysis.md) | [Lab](../labs/kubernetes-security/README.md) | Can configuration-level host privilege observations avoid becoming unverified exploitability claims? |
| [Host Telemetry Detection Lab: Nine Linux Rules, Their False Positives, and What They Cannot See](../linux-security/host-telemetry-detection-lab.md) | [Lab](../labs/linux-host-telemetry/README.md) | Can a small set of SQL host rules separate designed behaviour from suspicious behaviour on labeled telemetry while reporting a missing sensor or field as blind rather than clean? |
| [Secure CI/CD Pipeline Architecture and Trust Boundaries](../devsecops/secure-cicd-pipeline-design.md) | [Lab](../labs/secure-cicd/README.md) | Can malformed or incomplete scanner evidence ever satisfy release authorization? |
| [Infrastructure as Code Security and Policy Engineering](../devsecops/iac-security-and-policy-as-code.md) | [Lab](../labs/iac-policy/README.md) | Can unknown plan values and deletion of a modeled security control escape the policy gate? |
| [Software Supply-chain Evidence: SBOMs, Provenance, Signing, and Verification](../devsecops/supply-chain-sbom-signing.md) | [Lab](../labs/supply-chain/README.md) | Can valid-looking provenance or a verifier result be replayed for changed bytes, source or builder? |
| [Secrets Management Engineering: Identity, Delivery, Rotation and Runtime Exposure](../devsecops/secrets-management.md) | [Lab](../labs/request-lifecycle/README.md) | Does a warm secret cache fail closed after its freshness window when the provider is unavailable? |
| [Evidence-Preserving Security Scanning and Release Gates](../devsecops/evidence-preserving-security-pipelines.md) | [Lab](../labs/secure-cicd/README.md) | Can an outage or scanner failure silently become a clean release report? |
| [SecureObs: Customer-side CI Security Scanning with a Multi-tenant Findings Platform](../devsecops/secureobs-multitenant-security-scanner.md) | [Lab](../labs/secure-cicd/README.md) | Which findings-platform claims require full integration evidence beyond a passing local build gate? |
| [Attack Path Analysis: Preconditions, Reachability and Evidence-Backed Control Breaks](../threat-intel/attack-path-analysis.md) | [Lab](../labs/cicd-identity-escalation/README.md) | Does a policy-backed graph path correspond to an admitted sequence of authority transitions? |
| [Cloud Incident Case Studies: Evidence, Chronology, and Control Lessons](../threat-intel/cloud-breach-case-studies.md) | [Lab](../labs/mcp-tool-ssrf/README.md) | Can public incident disclosures support control lessons without inventing the missing exploit details? |

## Paired vulnerability investigations

- [URL-fetch SSRF](../vulnerability-research/mcp-tool-ssrf/index.md): actual isolated
  HTTP and TCP plus resolver-model tests.
- [Multi-tenant BOLA](../vulnerability-research/api-bola-multi-tenant/index.md): actual
  loopback HTTP and seeded-state assertions.
- [CI/CD identity escalation](../vulnerability-research/cicd-identity-escalation/index.md):
  Terraform-exported policy and locally signed assertion model; no STS execution.

## Historical research and unresolved validation

`docs/research/` contains retained reference material. Its existing archived URLs
remain archived/noindex under the lifecycle registry. Notices link each source to
its maintained replacement; the old code and explanations are not silently promoted
to current tested guidance. The active replacements above own ongoing experiments.

Read the [lab audit](lab-audit.md) and [verification record](../vulnerability-research/verification.md)
for actual tool availability, results and remaining validation gaps. Specific future
experiments are tracked in [open questions](open-questions.md).

## References

- [Evidence standards](evidence-standards.md)
- [Machine-readable article/lab mapping](research-coverage.json)
