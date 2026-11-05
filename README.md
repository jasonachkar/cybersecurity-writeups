# 🛡️ Cybersecurity Writeups & Learning

This repository contains **technical writeups, research notes, tutorials, and certification study materials** documenting my hands-on cybersecurity learning journey.
The focus is on **practical security engineering**, real-world attack scenarios, and defensible mitigation strategies across **cloud security, application security, identity, and DevSecOps**.

The content is written to reflect **how security is applied in production environments**, not just theoretical concepts.

---

## Start here — technical proof

Every item below is runnable on a laptop or a disposable VM. Each page says what was executed, what was only read from a
source, what is a policy model, and what was **not tested**; results that surprised me are kept in the write-ups.

1. [Docker image and runtime hardening lab](labs/docker-security/README.md) — an insecure and a hardened container measured from inside the container, a seccomp profile derived from `strace`, scanning, SBOM and local signing.
2. [Kubernetes lab](labs/kubernetes-security/README.md) — a live local cluster: workload identity, RBAC, admission and network reachability before and after, with four policy engines compared on one 16-case corpus.
3. [Host telemetry detection lab](linux-security/host-telemetry-detection-lab.md) — nine Linux detection rules as plain SQL, scored on labeled **synthetic** data, with the false positives and misses written down and a real-kernel `strace` cross-check.
4. [MCP tool-authorization lab](ai-security/mcp-tool-authorization-lab.md) — a policy gateway that holds against a stand-in agent that obeys every injected instruction.
5. [Vulnerability research](vulnerability-research/index.md) — three paired vulnerable/remediated studies on owned, isolated targets (tool SSRF, multi-tenant BOLA, CI/CD identity).
6. [Evidence standards](research-methodology/evidence-standards.md) — the T0–T4 rubric every page is held to.
7. [Lab reproducibility audit](research-methodology/lab-audit.md) — what each lab validates and what it does not.

## Technical proof

| Domain | Artifact | What I built | How it was validated | Security outcome | Link |
| --- | --- | --- | --- | --- | --- |
| Docker | Insecure vs hardened container stacks | One Go service in two configurations; a static Dockerfile/Compose gate; a seccomp profile derived from `strace` of the shipped binary; scan, SBOM and local cosign scripts | 38 static tests (in CI). One recorded run on a disposable Docker host: 85 of 85 runtime assertions, including a seccomp on/off/default control that attributes a denial to the filter | Insecure: root, 40 capabilities, no filter, Docker socket answering, host directory writable. Hardened: uid 65532, no capabilities, read-only root, 128 MiB / 64-PID limits enforced (OOM-killed at 512 MiB; 13 of 200 children started). Scan counts did **not** rank the images (0 vs 4 findings), so attack surface is measured directly (86 vs 10 executables) | [Docker lab](labs/docker-security/README.md) |
| Kubernetes | Baseline vs hardened workload on a live kind cluster | RBAC, Pod Security Admission, a CEL admission policy, default-deny NetworkPolicy (with an enforcement smoke test), a 16-case corpus run through PSA, VAP, Kyverno CLI and OPA | One fresh-cluster run: 83 of 83 assertions. Plus 16 manifest tests and 12 Rego tests; 23 Kyverno CLI tests; 45 manifests schema-valid | The over-granted identity could list `kube-system` secrets; the hardened one reads exactly one ConfigMap (403 elsewhere). The hardened pod reaches only its data tier. Found a false positive and a gap in my own existing Kyverno policy | [Kubernetes lab](labs/kubernetes-security/README.md) |
| Linux | Host telemetry detection | Nine SQL rules with identity-aware process ancestry, exceptions that need an owner and an expiry, deduplication, and a "blind" state for missing telemetry | 23 tests over 855 synthetic events in 42 labeled scenarios, with the confusion matrix pinned; a real `strace` capture from a throwaway container: 5 of 5 designed analogs alert, the negative control stays silent | 7 documented residual false positives and 2 documented misses; background noise raised 0 alerts; a missing sensor or field is reported blind, never clean. Synthetic data, author-written: a regression guard, not a field accuracy estimate | [Detection article](linux-security/host-telemetry-detection-lab.md) |
| AI / MCP | Tool-authorization gateway | A mock MCP-style stdio server and a gateway: allowlist with pinned descriptors, user-AND-agent scopes, session taint, single-use bound approvals, output validation, hash-chained audit | 33 mechanism tests against a real child process; 16 scenarios, 31 proposed calls, expectations declared before each step; side effects watched on an independent channel | 11 allowed, 5 gated for a human, 15 denied; the only side effects were the three in-policy or approved executions. No language model is involved: the agent is a deterministic stand-in | [MCP article](ai-security/mcp-tool-authorization-lab.md) |
| AppSec / AI | Paired studies on owned targets | Tool-SSRF, multi-tenant BOLA and CI/CD-identity experiments with vulnerable and remediated paths | Paired HTTP cases with seeded state; policy and container-path tests (tiers per study) | Same cases against both paths, with denial state checked; no cloud execution | [Vulnerability research](vulnerability-research/index.md) |
| DevSecOps | Supply chain and pipeline boundaries | Offline policy decisions for digest, provenance identity, source, builder and SBOM; untrusted-workflow and fail-closed scanner fixtures | Local positive and negative fixtures (see each lab's own status) | Unsigned, wrong-identity and changed-bytes cases rejected in the model; no real signing service | [Supply-chain lab](labs/supply-chain/README.md), [Secure CI/CD lab](labs/secure-cicd/README.md) |

Evidence labels used throughout: `tested locally` (executed, output kept), `source-reviewed` (read in a primary source, not executed),
`policy model` (a rule evaluated by a test, not enforced by the real system), and `requires-review` (no independent reviewer yet — every new
page carries it). "Tested locally" is not "proven in production"; each page lists what it did not test.

## Active deep dives

These four are the current focus. Each links to its lab and names the next experiment, because the open items are the honest part.

- **Docker security** — [lab](labs/docker-security/README.md). Next: AppArmor and rootless/user-namespace runs on a host that supports them, cgroup v2, and a CI job once the privileged lab has been tried on a hosted runner.
- **Kubernetes security** — [lab](labs/kubernetes-security/README.md). Next: Kyverno and Gatekeeper as live admission controllers, signed-image admission against a real signature, API-server audit logging, and binding the "approved" token label to something the pod author cannot set.
- **Linux security** — [article](linux-security/host-telemetry-detection-lab.md), [lab](labs/linux-host-telemetry/README.md). Next: a production sensor (auditd or eBPF) feeding the same rules, and the enrichment fields (parsed `ExecStart`, writer session, package ownership) that would remove the residual false positives without allowlisting tools.
- **AI/MCP security** — [article](ai-security/mcp-tool-authorization-lab.md), [lab](labs/mcp-tool-authorization/README.md). Next: a run against a real model, per-argument provenance in place of session-level taint, and anchoring the audit log's head hash.

## 📚 Contents Overview

- **Tutorials** – Step-by-step, implementation-focused guides
- **Research** – Deep dives into common security failures and attack patterns
- **Certification Notes** – Structured study notes with hands-on labs
- **Cloud & Identity Security** – Azure, Entra ID, Zero Trust, IAM
- **Application & API Security** – OWASP, OAuth, threat modeling
- **DevSecOps** – CI/CD security gates and supply chain protection

All writeups are written in Markdown and designed to be:
- Easy to read on GitHub
- Reusable for portfolio websites
- Expandable over time

---

## 📘 Tutorials

### 🔹 Building a Secure Azure Landing Zone
**Topics:** Azure, Cloud Security, IAM, Network Segmentation, Governance
A security-first guide to designing and deploying a production-ready Azure Landing Zone with enforced guardrails, identity governance, centralized logging, and policy-based compliance.

📂 Path:
```

docs/tutorials/azure-landing-zone/

```

---

### 🔹 OWASP API Security Top 10: Practical Mitigations
**Topics:** API Security, AppSec, OWASP, Node.js, .NET
A practical breakdown of the OWASP API Security Top 10, focusing on how vulnerabilities appear in real systems and how to mitigate them using secure backend design patterns.

📂 Path:
```

docs/tutorials/owasp-api-security-top-10/

```

---

### 🔹 Detection Engineering with Microsoft Sentinel
**Topics:** SIEM, Detection Engineering, KQL, Cloud Security
A hands-on guide to building high-signal detections in Microsoft Sentinel, focusing on identity abuse, lateral movement, and privilege escalation.

📂 Path:
```

docs/tutorials/detection-engineering-sentinel/

```

---

### 🔹 Implementing Security Gates in CI/CD Pipelines
**Topics:** DevSecOps, CI/CD, SAST, SCA, Supply Chain Security
A practical DevSecOps guide to integrating enforceable security gates into GitHub Actions and Azure DevOps pipelines.

📂 Path:
```

docs/tutorials/ci-cd-security-gates/

```

---

### 🔹 Securing Azure Entra ID (Zero Trust)
**Topics:** Azure Entra ID, IAM, Zero Trust, Identity Security
A real-world guide to hardening Azure Entra ID using Zero Trust principles, Conditional Access, MFA, PIM, and identity monitoring.

📂 Path:
```

docs/tutorials/securing-entra-id/

```

---

## 🔬 Research

### 🔹 Threat Modeling a Multi-Tenant SaaS Application (STRIDE)
**Topics:** Threat Modeling, STRIDE, SaaS, AppSec
A step-by-step threat modeling walkthrough applied to a multi-tenant SaaS CRM application, focusing on authorization, tenant isolation, and identity threats.

📂 Path:
```

docs/research/threat-modeling-saas/

```

---

### 🔹 Common OAuth 2.0 Misconfigurations and Exploits
**Topics:** OAuth, Authentication, Web Security
An analysis of real-world OAuth implementation flaws including redirect URI abuse, missing state validation, token leakage, and insecure flows.

📂 Path:
```

docs/research/oauth-misconfigurations/

```

---

### 🔹 Advanced Cloud Security Engineering (IAM, DevSecOps, Architecture, Detection)
**Topics:** Cloud Security, IAM, DevSecOps, Detection Engineering, Zero Trust, Azure
A production-grade research report covering workload identity federation & secretless CI/CD, policy-as-code (Rego/Checkov), supply-chain security (SBOM, Cosign/SLSA), micro-segmentation & Private Link, envelope encryption, and detection engineering with KQL.

📂 Path:
```

docs/research/enterprise-cloud-security-engineering/

```

---

## 🎓 Certification Notes

### 🔹 CompTIA Security+ Study Notes & Labs
**Topics:** Network Security, IAM, Cryptography, Incident Response
Comprehensive Security+ study notes covering all exam domains, reinforced with hands-on lab exercises and real-world context.

📂 Path:
```
docs/certification-notes/security-plus/
```

---

### 🔹 Microsoft AZ-900 Study Guide (Azure Fundamentals)
**Topics:** Cloud Concepts, Azure Architecture, Management, Governance
Study notes covering cloud fundamentals, core Azure services, identity management, compliance structures, and cost optimization.

📂 Path:
```
docs/certification-notes/az-900/
```

---

### 🔹 Google Cybersecurity Professional Certificate Notes
**Topics:** Linux, SQL, Python, SIEM, Incident Response, Network Security
Study guide covering core cybersecurity principles, CLI-based threat hunting, relational databases, security automation, and incident analysis.

📂 Path:
```
docs/certification-notes/google-cybersecurity/
```

---

### 🔹 Microsoft SC-500 Study Guide (Cloud & AI Security)
**Topics:** Entra ID IAM, Database/Network Controls, VM Security, Azure AI & GenAI Safety
Detailed study guide on implementing security controls for cloud workloads and securing generative AI architectures (e.g. prompt safety filters, vector db context filtering).

📂 Path:
```
docs/certification-notes/sc-500/
```

---

## 🛠️ Security Automation Scripts

### 🔹 Go Security Automation Tools
**Topics:** Go Lang, Cloud Security, AppSec, DevSecOps, Threat Detection
A collection of custom-built automation utilities written in Go to audit AWS SCPs, analyze IAM policies, scan Kubernetes RBAC configurations, validate JWT signatures, verify OAuth PKCE flows, and detect CloudTrail anomalies.

📂 Path:
```
docs/scripts/
```

---

## 🗂️ Repository Structure

```
cybersecurity-writeups/
│
├── README.md
│
├── docs/
│   ├── tutorials/
│   ├── research/
│   ├── certification-notes/
│   ├── scripts/
│   └── assets/
│
└── .gitignore
```

Each writeup lives in its own folder with a dedicated `README.md` to allow for expansion, diagrams, and additional sections over time.

---

## 🎯 Goals of This Repository

- Demonstrate applied cybersecurity knowledge
- Show structured security thinking and documentation skills
- Bridge the gap between theory and production security
- Serve as a reusable reference for future projects
- Support a professional cybersecurity portfolio

---

## 🔍 How to Use This Repo

- Browse topics directly on GitHub
- Link individual writeups from a portfolio website
- Reuse content for blogs or documentation
- Extend sections with diagrams, labs, or tooling

---

## 🚀 Future Additions

Planned or potential future topics include:
- Cloud detection engineering use cases
- Advanced identity attack simulations
- Purple team exercises
- Incident response playbooks
- Infrastructure threat modeling

---

## 📜 Disclaimer

All content in this repository is for **educational and defensive purposes only**.
No offensive exploitation techniques are provided beyond what is necessary to understand and mitigate security risks.

---

## 👤 Author

This repository reflects my ongoing journey in cybersecurity, with a focus on **cloud security, application security, identity, and DevSecOps**.

Feedback, discussion, and constructive suggestions are always welcome.
## Applied research and reproducible experiments

Start with the [research methodology](research-methodology/index.md),
[evidence standards](research-methodology/evidence-standards.md), and
[research/lab index](research-methodology/research-index.md).
The [vulnerability-research studies](vulnerability-research/index.md) compare owned
local SSRF, tenant-authorization and CI/CD identity targets with their remediations.
The [verification record](vulnerability-research/verification.md) distinguishes
actual local behavior, policy models, source review and work not tested.

Canonical source belongs in `main` through a reviewed PR. The pipeline builds
MkDocs from source, verifies it, then publishes that exact static artifact to
`gh-pages`; generated HTML is not edited independently. See the
[deployment review](publishing/deployment-review.md).

<!-- AUTOGENERATED_INDEX_START -->
## 📚 Index

_This section is autogenerated. Do not edit entries here directly; update each writeup’s front matter instead._

### ☁️ Cloud Security

- [AWS IAM at Scale: Federation, Delegation, and Guardrails](cloud-security/iam-at-scale.md) —  · 2026-07-25
- [AWS Multi-Account Landing Zones: Guardrails and Control-Plane Isolation](cloud-security/multi-account-landing-zones.md) —  · 2026-07-25
- [Cloud Detection Engineering: Durable Telemetry, High-Signal Analytics and Safe Response](cloud-security/cloud-detection-and-response.md) —  · 2026-07-25
- [Cloud Network Segmentation and Egress Control: Routing, Private Endpoints and Failure Domains](cloud-security/cloud-network-segmentation.md) —  · 2026-07-25
- [Cloud Security overview](cloud-security/index.md) —  · 2026-07-25 · 2 min
- [Kubernetes Multi-tenancy: Boundaries, Isolation, and Operations](cloud-security/kubernetes-multi-tenancy.md) —  · 2026-07-25
- [Serverless Security Engineering: Event Trust, Function Identity and Runtime Reuse](cloud-security/serverless-security.md) —  · 2026-07-25

### 💻 Application Security

- [API and Microservice Trust Boundaries: Workload Identity, User Context and Downstream Authorization](appsec/api-microservices-threat-modeling.md) —  · 2026-07-25
- [Application Security overview](appsec/index.md) —  · 2026-07-25 · 2 min
- [Engineering Tenant Isolation for a Multi-tenant SaaS Platform](appsec/saas-multitenancy-isolation.md) —  · 2026-07-25
- [Layered Runtime Application Protection: WAF, In-Process Controls and eBPF Enforcement](appsec/runtime-protection-rasp-waf.md) —  · 2026-07-25
- [OAuth 2.0 and OpenID Connect Security Engineering](appsec/oauth2-oidc-deep-dive.md) —  · 2026-07-25
- [Threat-Driven Security Architecture for AI Agents](appsec/ai-agent-security.md) —  · 2026-07-23

### 🛡️ DevSecOps

- [Evidence-Preserving Security Scanning and Release Gates](devsecops/evidence-preserving-security-pipelines.md) —  · 2026-10-22
- [DevSecOps overview](devsecops/index.md) —  · 2026-07-25 · 2 min
- [Infrastructure as Code Security and Policy Engineering](devsecops/iac-security-and-policy-as-code.md) —  · 2026-07-25
- [Secrets Management Engineering: Identity, Delivery, Rotation and Runtime Exposure](devsecops/secrets-management.md) —  · 2026-07-25
- [Secure CI/CD Pipeline Architecture and Trust Boundaries](devsecops/secure-cicd-pipeline-design.md) —  · 2026-07-25
- [SecureObs: Customer-side CI Security Scanning with a Multi-tenant Findings Platform](devsecops/secureobs-multitenant-security-scanner.md) —  · 2026-07-25
- [Software Supply-chain Evidence: SBOMs, Provenance, Signing, and Verification](devsecops/supply-chain-sbom-signing.md) —  · 2026-07-25

### AI Security

- [MCP Tool Authorization Lab: A Gateway That Holds When the Model Does Not](ai-security/mcp-tool-authorization-lab.md) —  · 2026-11-05
- [AI Security overview](ai-security/index.md) —  · 2026-10-22 · 1 min
- [Evidence-Driven AI Agent and MCP Security](ai-security/evidence-driven-agent-security.md) —  · 2026-10-22

### Linux Security

- [Host Telemetry Detection Lab: Nine Linux Rules, Their False Positives, and What They Cannot See](linux-security/host-telemetry-detection-lab.md) —  · 2026-11-05
- [Linux Host Analysis Without Invented Attack Paths](linux-security/evidence-driven-host-analysis.md) —  · 2026-10-22
- [Linux Security overview](linux-security/index.md) —  · 2026-10-22 · 1 min

### 🕵️ Threat Intelligence

- [Attack Path Analysis: Preconditions, Reachability and Evidence-Backed Control Breaks](threat-intel/attack-path-analysis.md) —  · 2026-07-25
- [Cloud Incident Case Studies: Evidence, Chronology, and Control Lessons](threat-intel/cloud-breach-case-studies.md) —  · 2026-07-25
- [Threat Intelligence overview](threat-intel/index.md) —  · 2026-07-25 · 2 min

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

- [CompTIA Security+ SY0-701 study notes](docs/certification-notes/security-plus/README.md) —  · 2026-07-25 · 4 min
- [Microsoft SC-500 study notes](docs/certification-notes/sc-500/README.md) —  · 2026-07-25 · 6 min
- [Google Cybersecurity Certificate Study Guide](docs/certification-notes/google-cybersecurity/README.md) — Linux, SQL, Python, SIEM (+1) · 2026-06 · 20 min
- [Microsoft AZ-900: Azure Fundamentals Study Guide](docs/certification-notes/az-900/README.md) — Azure, Cloud Security, Fundamentals · 2026-06 · 15 min
<!-- AUTOGENERATED_INDEX_END -->
