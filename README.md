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

## 🎓 Certification Notes

### 🔹 CompTIA Security+ Study Notes & Labs
**Topics:** Network Security, IAM, Cryptography, Incident Response  
Comprehensive Security+ study notes covering all exam domains, reinforced with hands-on lab exercises and real-world context.

📂 Path:
```

docs/certification-notes/security-plus/

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
