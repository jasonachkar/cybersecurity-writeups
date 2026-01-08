# Security+ SY0-701 Practice Questions

## Domain 1: General Security Concepts (12%)

### Question 1
A company implements a firewall to block unauthorized traffic. What type of control is this?

A. Detective  
B. Corrective  
C. Preventive  
D. Compensating

<details>
<summary>Answer</summary>

**C. Preventive**

A firewall blocks threats before they can cause harm, making it a preventive control. Detective controls identify threats during or after occurrence. Corrective controls fix issues after an incident. Compensating controls are alternatives when primary controls aren't feasible.
</details>

---

### Question 2
Which component of the CIA triad is MOST directly addressed by implementing hashing?

A. Confidentiality  
B. Integrity  
C. Availability  
D. Non-repudiation

<details>
<summary>Answer</summary>

**B. Integrity**

Hashing provides integrity verification by creating a unique fingerprint of data. If the data changes, the hash changes, indicating tampering. Confidentiality requires encryption, and availability requires redundancy/uptime measures.
</details>

---

### Question 3
A security administrator is implementing a zero trust architecture. Which principle should be the PRIMARY focus?

A. Trust all internal network traffic  
B. Never trust, always verify  
C. Trust but verify periodically  
D. Trust users after initial authentication

<details>
<summary>Answer</summary>

**B. Never trust, always verify**

Zero trust assumes no implicit trust regardless of network location. Every access request must be verified regardless of whether it originates inside or outside the network perimeter.
</details>

---

### Question 4
Which cryptographic algorithm would be BEST for encrypting a large database at rest?

A. RSA  
B. AES  
C. Diffie-Hellman  
D. DSA

<details>
<summary>Answer</summary>

**B. AES**

AES is a symmetric algorithm that is fast and efficient for encrypting large amounts of data. RSA and other asymmetric algorithms are slower and typically used for key exchange or digital signatures, not bulk encryption.
</details>

---

### Question 5
A developer adds random data to passwords before hashing. What is this technique called?

A. Key stretching  
B. Salting  
C. Steganography  
D. Obfuscation

<details>
<summary>Answer</summary>

**B. Salting**

Salting adds random data to passwords before hashing to prevent rainbow table attacks. Each password gets a unique salt, so even identical passwords produce different hashes.
</details>

---

## Domain 2: Threats, Vulnerabilities & Mitigations (22%)

### Question 6
An attacker sends emails appearing to be from the CEO requesting wire transfers. What type of attack is this?

A. Phishing  
B. Spear phishing  
C. Whaling  
D. Vishing

<details>
<summary>Answer</summary>

**C. Whaling**

Whaling specifically targets high-profile individuals like executives. While this is a type of spear phishing, the term "whaling" is more specific when executives are the target and typically involves business email compromise scenarios.
</details>

---

### Question 7
A security analyst discovers malware that encrypts files and demands payment. What type of malware is this?

A. Spyware  
B. Rootkit  
C. Ransomware  
D. Logic bomb

<details>
<summary>Answer</summary>

**C. Ransomware**

Ransomware encrypts files and demands payment for the decryption key. Spyware monitors activity, rootkits hide malware presence, and logic bombs trigger on specific conditions.
</details>

---

### Question 8
Which threat actor type is MOST likely to have extensive resources and conduct long-term espionage campaigns?

A. Hacktivist  
B. Script kiddie  
C. Nation-state  
D. Insider threat

<details>
<summary>Answer</summary>

**C. Nation-state**

Nation-state actors have government backing, extensive resources, high sophistication, and often conduct Advanced Persistent Threats (APTs) focused on espionage and strategic objectives.
</details>

---

### Question 9
An attacker intercepts and alters communications between two parties without their knowledge. What type of attack is this?

A. Replay attack  
B. Man-in-the-middle  
C. Session hijacking  
D. DNS poisoning

<details>
<summary>Answer</summary>

**B. Man-in-the-middle**

A man-in-the-middle (MitM) attack involves intercepting and potentially altering communications between two parties. Replay attacks reuse captured data, session hijacking steals existing sessions, and DNS poisoning corrupts DNS responses.
</details>

---

### Question 10
Which attack involves injecting malicious SQL statements through user input fields?

A. Cross-site scripting  
B. SQL injection  
C. Buffer overflow  
D. CSRF

<details>
<summary>Answer</summary>

**B. SQL injection**

SQL injection inserts malicious SQL commands through input fields to manipulate databases. XSS injects client-side scripts, buffer overflow exceeds memory boundaries, and CSRF tricks users into unwanted actions.
</details>

---

## Domain 3: Security Architecture (18%)

### Question 11
Which network zone should contain publicly accessible web servers?

A. Internal network  
B. DMZ  
C. Management network  
D. Guest network

<details>
<summary>Answer</summary>

**B. DMZ**

The DMZ (Demilitarized Zone) is a perimeter network that hosts public-facing services while isolating them from the internal network. This provides defense in depth if the public servers are compromised.
</details>

---

### Question 12
A company wants to ensure users can access multiple applications with a single set of credentials. What should they implement?

A. MFA  
B. Federation  
C. SSO  
D. RBAC

<details>
<summary>Answer</summary>

**C. SSO**

Single Sign-On (SSO) allows users to authenticate once and access multiple applications without re-entering credentials. Federation enables SSO across organizations, MFA adds authentication factors, and RBAC is an access control model.
</details>

---

### Question 13
In a cloud shared responsibility model using IaaS, who is responsible for operating system security?

A. Cloud provider  
B. Customer  
C. Shared responsibility  
D. Third-party vendor

<details>
<summary>Answer</summary>

**B. Customer**

In IaaS, the customer is responsible for everything from the operating system up (OS, applications, data). The provider manages the underlying infrastructure (hardware, virtualization, networking).
</details>

---

### Question 14
Which access control model uses labels and clearances to determine access?

A. DAC  
B. MAC  
C. RBAC  
D. ABAC

<details>
<summary>Answer</summary>

**B. MAC**

Mandatory Access Control (MAC) uses security labels (e.g., Top Secret, Secret) and user clearances. Access is granted when the user's clearance equals or exceeds the resource's classification. Common in military/government environments.
</details>

---

### Question 15
A company needs to protect sensitive data in a database while maintaining the ability to perform operations on it. What technique should they use?

A. Encryption  
B. Hashing  
C. Tokenization  
D. Masking

<details>
<summary>Answer</summary>

**C. Tokenization**

Tokenization replaces sensitive data with non-sensitive tokens while maintaining referential integrity. The original data is stored separately in a token vault. This allows operations to continue without exposing actual sensitive data.
</details>

---

## Domain 4: Security Operations (28%)

### Question 16
Which phase of incident response involves isolating affected systems?

A. Identification  
B. Containment  
C. Eradication  
D. Recovery

<details>
<summary>Answer</summary>

**B. Containment**

Containment focuses on limiting damage and preventing spread by isolating affected systems. Identification detects the incident, eradication removes the threat, and recovery restores normal operations.
</details>

---

### Question 17
During a forensic investigation, which type of evidence should be collected FIRST?

A. Hard drive contents  
B. RAM contents  
C. Backup tapes  
D. Network logs

<details>
<summary>Answer</summary>

**B. RAM contents**

According to the order of volatility, RAM (volatile memory) should be collected first as it is lost when power is removed. Hard drives, backups, and stored logs are more persistent and can be collected later.
</details>

---

### Question 18
What is the PRIMARY function of a SIEM?

A. Block malicious traffic  
B. Encrypt sensitive data  
C. Aggregate and correlate security logs  
D. Scan for vulnerabilities

<details>
<summary>Answer</summary>

**C. Aggregate and correlate security logs**

SIEM (Security Information and Event Management) collects logs from multiple sources, correlates events to identify threats, provides alerting, and supports compliance reporting.
</details>

---

### Question 19
A company can tolerate a maximum of 4 hours of downtime. What metric does this represent?

A. RPO  
B. RTO  
C. MTTR  
D. MTBF

<details>
<summary>Answer</summary>

**B. RTO**

Recovery Time Objective (RTO) is the maximum acceptable downtime. RPO is the maximum acceptable data loss, MTTR is the average recovery time, and MTBF is the average time between failures.
</details>

---

### Question 20
Which backup type takes the LEAST amount of time to complete but the LONGEST to restore?

A. Full  
B. Incremental  
C. Differential  
D. Snapshot

<details>
<summary>Answer</summary>

**B. Incremental**

Incremental backups only back up changes since the last backup of any type, making them fastest to complete. However, restoration requires the full backup plus all subsequent incremental backups, making it slowest to restore.
</details>

---

## Domain 5: Security Program Management (20%)

### Question 21
Which document provides high-level statements about an organization's security goals?

A. Standard  
B. Procedure  
C. Guideline  
D. Policy

<details>
<summary>Answer</summary>

**D. Policy**

Policies are high-level documents that state organizational intent and goals. Standards are mandatory requirements, procedures are step-by-step instructions, and guidelines are recommendations.
</details>

---

### Question 22
What is the formula for calculating Annual Loss Expectancy (ALE)?

A. ALE = SLE × ARO  
B. ALE = Asset Value × Exposure Factor  
C. ALE = Threat × Vulnerability  
D. ALE = RTO × RPO

<details>
<summary>Answer</summary>

**A. ALE = SLE × ARO**

ALE (Annual Loss Expectancy) = SLE (Single Loss Expectancy) × ARO (Annual Rate of Occurrence). SLE is calculated as Asset Value × Exposure Factor.
</details>

---

### Question 23
A company is evaluating a cloud provider's security practices. Which report provides assurance about security controls?

A. Penetration test report  
B. SOC 2 report  
C. Risk assessment  
D. Business impact analysis

<details>
<summary>Answer</summary>

**B. SOC 2 report**

SOC 2 (Service Organization Control 2) reports provide assurance about a service organization's controls related to security, availability, processing integrity, confidentiality, and privacy.
</details>

---

### Question 24
Which regulation specifically addresses the protection of healthcare data in the United States?

A. GDPR  
B. PCI-DSS  
C. HIPAA  
D. SOX

<details>
<summary>Answer</summary>

**C. HIPAA**

HIPAA (Health Insurance Portability and Accountability Act) protects healthcare data in the US. GDPR is EU privacy regulation, PCI-DSS is for payment cards, and SOX is for financial reporting.
</details>

---

### Question 25
What is the PRIMARY purpose of security awareness training?

A. Ensure compliance with regulations  
B. Reduce human-based security risks  
C. Document security policies  
D. Perform vulnerability assessments

<details>
<summary>Answer</summary>

**B. Reduce human-based security risks**

Security awareness training's primary purpose is to reduce the human element of security risk by educating employees about threats like phishing and social engineering. While it supports compliance, risk reduction is the primary goal.
</details>

---

## Scenario-Based Questions

### Question 26
A company experiences a ransomware attack. The security team isolates infected systems and is now removing the malware. Which IR phase are they in?

A. Containment  
B. Eradication  
C. Recovery  
D. Lessons Learned

<details>
<summary>Answer</summary>

**B. Eradication**

Removing the malware is part of the eradication phase. Containment (isolation) was already completed. Recovery involves restoring systems, and lessons learned is the final documentation phase.
</details>

---

### Question 27
An organization wants to implement the MOST secure wireless authentication method for enterprise use. What should they deploy?

A. WPA2-Personal  
B. WPA3-Personal  
C. WPA2-Enterprise  
D. WEP

<details>
<summary>Answer</summary>

**C. WPA2-Enterprise** (or WPA3-Enterprise if available)

Enterprise modes use 802.1X authentication with a RADIUS server, providing individual user credentials rather than shared passwords. WEP is deprecated and insecure, and Personal modes use shared passphrases.
</details>

---

### Question 28
A developer discovers their application is vulnerable to XSS attacks. What is the BEST mitigation?

A. Parameterized queries  
B. Input validation and output encoding  
C. Rate limiting  
D. TLS encryption

<details>
<summary>Answer</summary>

**B. Input validation and output encoding**

XSS is mitigated by validating input and encoding output to prevent script injection. Parameterized queries prevent SQL injection, rate limiting prevents brute force/DoS, and TLS protects data in transit.
</details>

---

### Question 29
A security analyst notices failed login attempts from a single IP address trying different usernames with the same password. What attack is occurring?

A. Brute force  
B. Dictionary attack  
C. Password spraying  
D. Credential stuffing

<details>
<summary>Answer</summary>

**C. Password spraying**

Password spraying uses one password against many accounts to avoid lockouts. Brute force tries all combinations on one account, dictionary attacks use word lists, and credential stuffing uses stolen credentials from other breaches.
</details>

---

### Question 30
A company stores customer credit card data. Which compliance framework MUST they follow?

A. HIPAA  
B. SOX  
C. PCI-DSS  
D. GDPR

<details>
<summary>Answer</summary>

**C. PCI-DSS**

Payment Card Industry Data Security Standard (PCI-DSS) is mandatory for any organization that stores, processes, or transmits credit card data. HIPAA is for healthcare, SOX for financial reporting, and GDPR for EU personal data.
</details>

---

## Performance-Based Question Example

### Question 31 (PBQ-Style)
Match each attack type to its correct description and primary mitigation:

**Attacks:**
1. SQL Injection
2. Cross-Site Scripting (XSS)
3. Man-in-the-Middle
4. Phishing
5. Buffer Overflow

**Descriptions:**
A. Attacker intercepts communication between two parties
B. Malicious scripts injected into web pages viewed by users
C. Malicious SQL commands inserted through input fields
D. Deceptive emails trick users into revealing credentials
E. Data written beyond allocated memory space

**Mitigations:**
W. Security awareness training
X. Input validation and memory-safe programming
Y. Parameterized queries
Z. TLS/certificate pinning
V. Input validation and output encoding

<details>
<summary>Answer</summary>

| Attack | Description | Mitigation |
|--------|-------------|------------|
| 1. SQL Injection | C | Y |
| 2. XSS | B | V |
| 3. Man-in-the-Middle | A | Z |
| 4. Phishing | D | W |
| 5. Buffer Overflow | E | X |
</details>

---

## Answer Key Summary

| Q# | Answer | Domain |
|----|--------|--------|
| 1 | C | 1 |
| 2 | B | 1 |
| 3 | B | 1 |
| 4 | B | 1 |
| 5 | B | 1 |
| 6 | C | 2 |
| 7 | C | 2 |
| 8 | C | 2 |
| 9 | B | 2 |
| 10 | B | 2 |
| 11 | B | 3 |
| 12 | C | 3 |
| 13 | B | 3 |
| 14 | B | 3 |
| 15 | C | 3 |
| 16 | B | 4 |
| 17 | B | 4 |
| 18 | C | 4 |
| 19 | B | 4 |
| 20 | B | 4 |
| 21 | D | 5 |
| 22 | A | 5 |
| 23 | B | 5 |
| 24 | C | 5 |
| 25 | B | 5 |
| 26 | B | 4 |
| 27 | C | 3 |
| 28 | B | 2 |
| 29 | C | 2 |
| 30 | C | 5 |
