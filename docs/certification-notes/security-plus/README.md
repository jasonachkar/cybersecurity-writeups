---
title: "CompTIA Security+ Study Notes & Labs"
type: certification-notes
tags: [Security+, Certification, Network Security, IAM, Cryptography, Incident Response]
date: 2024-08
readingTime: 25
---

# CompTIA Security+ Study Notes & Labs

## Introduction

These notes consolidate my preparation for the CompTIA Security+ certification into a structured, practical study guide. Rather than focusing on rote memorization, the emphasis is on **understanding security concepts, how they interrelate, and how they apply in real-world environments**.

Each section includes:
- Concept explanations
- Real-world context
- Practical examples and labs
- Exam-focused insights

This document also serves as a long-term reference for foundational cybersecurity knowledge.

---

## Domain 1: General Security Concepts

### CIA Triad

The CIA triad defines the core objectives of information security:

- **Confidentiality** – Prevent unauthorized disclosure of information
- **Integrity** – Ensure data accuracy and prevent unauthorized modification
- **Availability** – Ensure systems and data are accessible when needed

Security controls often support more than one pillar.

---

### Authentication vs Authorization

- **Authentication** verifies identity
- **Authorization** determines access rights

A system can authenticate a user correctly while still failing authorization — a common cause of security breaches.

---

### Non-Repudiation

Ensures that an action cannot be denied after it occurs.

Examples:
- Digital signatures
- Audit logs
- Transaction records

---

## Domain 2: Threats, Vulnerabilities, and Mitigations

### Common Threat Actors

- Script kiddies
- Hacktivists
- Organized crime
- Nation-state actors
- Insider threats

Each actor has different motivations, resources, and attack patterns.

---

### Malware Types

- **Virus** – Requires user action to spread
- **Worm** – Self-propagates without user interaction
- **Trojan** – Disguised as legitimate software
- **Ransomware** – Encrypts data for extortion
- **Rootkit** – Hides malicious activity

---

### Social Engineering Attacks

- Phishing
- Spear phishing
- Whaling
- Pretexting
- Tailgating

Humans are often the weakest link in security systems.

---

## Domain 3: Security Architecture and Design

### Defense in Depth

Security should be layered so that the failure of one control does not result in total compromise.

Examples:
- Firewalls + IDS + endpoint protection
- MFA + RBAC + monitoring

---

### Network Segmentation

Separating networks reduces lateral movement.

Types:
- VLANs
- Subnets
- Security zones
- Microsegmentation

Flat networks increase breach impact.

---

### Zero Trust Principles

- Never trust, always verify
- Assume breach
- Enforce least privilege
- Continuous verification

Identity becomes the new perimeter.

---

## Domain 4: Security Operations

### Logging and Monitoring

Logs provide visibility into:
- Authentication events
- System changes
- Network traffic
- Application behavior

Without logs, incident response is guesswork.

---

### Incident Response Lifecycle

1. Preparation
2. Identification
3. Containment
4. Eradication
5. Recovery
6. Lessons Learned

Skipping preparation significantly increases damage during incidents.

---

### Digital Forensics Basics

Key principles:
- Preserve evidence
- Maintain chain of custody
- Minimize system changes
- Document everything

---

## Domain 5: Identity and Access Management (IAM)

### Authentication Factors

- Something you know (password)
- Something you have (token, phone)
- Something you are (biometrics)

MFA significantly reduces account compromise risk.

---

### Access Control Models

- **DAC** – Owner-controlled access
- **MAC** – Central authority
- **RBAC** – Role-based access
- **ABAC** – Attribute-based access

RBAC is the most common in enterprise environments.

---

### Privileged Access Management

Administrative accounts should:
- Be limited in number
- Use MFA
- Be monitored
- Use just-in-time access

Standing privilege is a major risk.

---

## Domain 6: Cryptography and PKI

### Encryption Types

- **Symmetric** – Fast, shared secret
- **Asymmetric** – Slower, public/private keys
- **Hashing** – One-way integrity checks

---

### Common Algorithms

- AES (symmetric)
- RSA (asymmetric)
- ECC (asymmetric)
- SHA-256 (hashing)

Algorithm strength depends on proper implementation.

---

### Public Key Infrastructure (PKI)

PKI enables:
- Secure communication
- Digital certificates
- Trust validation

Key components:
- Certificate Authority (CA)
- Certificates
- Revocation mechanisms

---

## Domain 7: Risk Management

### Risk Components

- Threat
- Vulnerability
- Impact
- Likelihood

Risk = Threat × Vulnerability × Impact

---

### Risk Treatment Options

- Accept
- Avoid
- Transfer
- Mitigate

Not all risks should be mitigated.

---

### Business Impact Analysis (BIA)

Identifies:
- Critical systems
- Recovery time objectives (RTO)
- Recovery point objectives (RPO)

Supports disaster recovery planning.

---

## Hands-On Labs

### Lab 1: Network Security

- Configure firewall rules
- Identify open ports
- Simulate blocked traffic
- Analyze logs

---

### Lab 2: IAM Hardening

- Enforce MFA
- Create RBAC roles
- Test privilege escalation attempts

---

### Lab 3: Cryptography

- Generate key pairs
- Encrypt and decrypt files
- Verify digital signatures

---

## Exam Tips and Strategies

- Focus on **why**, not just definitions
- Read questions carefully for keywords
- Eliminate obviously incorrect answers
- Understand scenario-based questions

Security+ tests conceptual understanding more than memorization.

---

## Key Lessons Learned

- Security concepts are deeply interconnected
- Identity and access control underpin most defenses
- Hands-on labs reinforce theoretical knowledge
- Foundational security knowledge scales into advanced domains

---

## Conclusion

The CompTIA Security+ certification provided a strong foundation across multiple security domains, from network defense to cryptography and incident response. These notes continue to serve as a reference point for more advanced studies in cloud security, application security, and DevSecOps.

This certification reinforced the importance of **holistic security thinking** and understanding how individual controls contribute to broader risk reduction.

---

## References

- CompTIA Security+ Exam Objectives
- NIST Cybersecurity Framework
- CIS Critical Security Controls
- MITRE ATT&CK Framework
