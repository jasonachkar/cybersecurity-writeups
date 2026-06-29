# 🛡️ Cybersecurity Writeups & Learning

This repository contains **technical writeups, research notes, tutorials, and certification study materials** documenting my hands-on cybersecurity learning journey.  
The focus is on **practical security engineering**, real-world attack scenarios, and defensible mitigation strategies across **cloud security, application security, identity, and DevSecOps**.

The content is written to reflect **how security is applied in production environments**, not just theoretical concepts.

---

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
<!-- AUTOGENERATED_INDEX_START -->
## 📚 Index

_This section is autogenerated. Do not edit entries here directly; update each writeup’s front matter instead._

### ☁️ Cloud Security

- [Cloud Detection and Response: Designing Resilient SIEM Pipelines, CloudTrail Auditing, and Automated Response](cloud-security/cloud-detection-and-response.md) — Detection Engineering, CloudTrail, Incident Response, SIEM (+1) · 2026-06 · 18 min
- [Cloud Network Segmentation: VPC Architecture, Transit Gateway Routing, and PrivateLink Integration](cloud-security/cloud-network-segmentation.md) — VPC, Transit Gateway, PrivateLink, Network Security (+1) · 2026-06 · 18 min
- [Enterprise IAM at Scale: Workload Identity, Permission Boundaries, and Trust Architecture](cloud-security/iam-at-scale.md) — AWS IAM, Workload Identity, OIDC, ABAC (+1) · 2026-06 · 20 min
- [Enterprise Multi-Account Landing Zone Architecture and Control Plane Isolation](cloud-security/multi-account-landing-zones.md) — AWS Organizations, SCP, Landing Zones, Governance (+1) · 2026-06 · 18 min
- [Kubernetes Multi-Tenancy: Hardening RBAC, NetworkPolicies, and Workload Isolation Boundaries](cloud-security/kubernetes-multi-tenancy.md) — Kubernetes, Multi-Tenancy, OPA Gatekeeper, NetworkPolicy (+1) · 2026-06 · 22 min
- [Serverless Security: Function-Level IAM, Ephemeral Lifecycles, and Runtime Isolation](cloud-security/serverless-security.md) — Serverless, AWS Lambda, API Gateway, IAM (+1) · 2026-06 · 16 min

### 💻 Application Security

- [API and Microservices Threat Modeling: STRIDE, Trust Boundaries, and Header Propagation Security](appsec/api-microservices-threat-modeling.md) — API Security, Threat Modeling, STRIDE, Microservices (+1) · 2026-06 · 16 min
- [OAuth 2.0 and OIDC Security Deep Dive: PKCE, Token Validation, and Federation Hardening](appsec/oauth2-oidc-deep-dive.md) — OAuth 2.0, OIDC, PKCE, Authentication (+1) · 2026-06 · 20 min
- [Runtime Application Protection: Comparing WAF and RASP Architectures, eBPF Filtering, and Evasion Mitigation](appsec/runtime-protection-rasp-waf.md) — WAF, RASP, eBPF, Runtime Security (+1) · 2026-06 · 16 min
- [SaaS Multi-Tenancy Isolation Patterns: Database Segregation, PostgreSQL RLS, and Session Context Security](appsec/saas-multitenancy-isolation.md) — Multi-Tenancy, Database Security, PostgreSQL RLS, SaaS (+1) · 2026-06 · 20 min

### 🛡️ DevSecOps

- [Enterprise Secrets Management: HashiCorp Vault, Dynamic Provisioning, and Memory Protection](devsecops/secrets-management.md) — Secrets Management, HashiCorp Vault, Cloud Security, Encryption (+1) · 2026-06 · 18 min
- [IaC Security and Policy as Code: Hardening Terraform State, Rego Policy Engine, and Drift Controls](devsecops/iac-security-and-policy-as-code.md) — Infrastructure as Code, Policy as Code, Open Policy Agent, Terraform (+1) · 2026-06 · 18 min
- [Secure CI/CD Pipeline Design: Runner Hardening, Workload Identity, and Pipeline Integrity](devsecops/secure-cicd-pipeline-design.md) — CI/CD Security, DevSecOps, GitHub Actions, Pipeline Hardening (+1) · 2026-06 · 18 min
- [Software Supply Chain Security: SBOM Generation, Container Signing, and SLSA Compliance](devsecops/supply-chain-sbom-signing.md) — Supply Chain, SBOM, Cosign, Sigstore (+1) · 2026-06 · 20 min

### 🕵️ Threat Intelligence

- [Advanced Cloud Attack Path Analysis: Mapping Multi-Stage Exploits to the MITRE ATT&CK Matrix](threat-intel/attack-path-analysis.md) — Threat Intelligence, Attack Paths, MITRE ATT&CK, Cloud Security (+1) · 2026-06 · 20 min
- [Cloud Breach Case Studies: Technical Autopsy of Capital One, Uber, and CircleCI Compromises](threat-intel/cloud-breach-case-studies.md) — Threat Intelligence, Case Studies, Cloud Breaches, Incident Response (+1) · 2026-06 · 20 min

### 📘 Tutorials

- [Azure Landing Zone Security](docs/tutorials/azure-landing-zone/README.md) — Security, Azure · 2026-06 · 21 min
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
- [Microsoft SC-500: Implementing Security Controls for Cloud and AI Workloads Study Guide](docs/certification-notes/sc-500/README.md) — Azure, Cloud Security, AI Workloads, Governance · 2026-06 · 25 min
<!-- AUTOGENERATED_INDEX_END -->
