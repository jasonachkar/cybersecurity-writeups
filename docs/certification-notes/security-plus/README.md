# CompTIA Security+ SY0-701 Study Guide

## Exam Overview

| Attribute | Details |
|-----------|---------|
| Exam Code | SY0-701 |
| Questions | Maximum 90 |
| Duration | 90 minutes |
| Passing Score | 750/900 (~83%) |
| Question Types | Multiple choice + Performance-based (PBQs) |
| Validity | 3 years |
| Cost | ~$404 USD |

**Exam Strategy:**
- PBQs often appear early - consider flagging and returning to them
- Unanswered questions count as wrong - always guess if unsure
- ~1 minute per question average

---

## Domain Weightings

| Domain | Weight | Focus Areas |
|--------|--------|-------------|
| 1. General Security Concepts | 12% | Foundations, CIA, Zero Trust, Crypto |
| 2. Threats, Vulnerabilities & Mitigations | 22% | Threat actors, Attacks, Indicators |
| 3. Security Architecture | 18% | Network security, Cloud, IAM |
| 4. Security Operations | 28% | Monitoring, IR, Forensics |
| 5. Security Program Management | 20% | GRC, Risk, Compliance |

---

## Domain 1: General Security Concepts (12%)

### 1.1 Security Controls

**Control Categories:**

| Category | Description | Examples |
|----------|-------------|----------|
| Technical | Implemented via technology | Firewalls, encryption, ACLs |
| Managerial | Administrative policies/procedures | Risk assessments, security policies |
| Operational | Day-to-day procedures | Security guards, awareness training |
| Physical | Tangible protection measures | Locks, fences, CCTV |

**Control Types:**

| Type | Purpose | Examples |
|------|---------|----------|
| Preventive | Stop incidents before they occur | Firewalls, locks, training |
| Detective | Identify incidents as/after they occur | IDS, logs, audits, motion sensors |
| Corrective | Remediate after an incident | Patching, restoring backups |
| Deterrent | Discourage threat actors | Warning signs, security cameras |
| Compensating | Alternative when primary control isn't feasible | Increased monitoring when can't patch |
| Directive | Direct behavior through policy | Acceptable use policies |

### 1.2 Fundamental Security Concepts

**CIA Triad:**

```
         Confidentiality
              /\
             /  \
            /    \
           /      \
          /________\
    Integrity    Availability
```

| Principle | Definition | Controls |
|-----------|------------|----------|
| Confidentiality | Prevent unauthorized disclosure | Encryption, access controls, MFA |
| Integrity | Data is accurate and unaltered | Hashing, digital signatures, checksums |
| Availability | Systems accessible when needed | Redundancy, backups, load balancing |

**Non-Repudiation:**
- Proves a message/transaction occurred
- Cannot deny sending/receiving
- Achieved through: Digital signatures, audit logs, timestamps

**AAA Framework:**

| Component | Function | Examples |
|-----------|----------|----------|
| Authentication | Verify identity | Passwords, biometrics, tokens |
| Authorization | Grant permissions | RBAC, ACLs, permissions |
| Accounting | Track activities | Logs, audit trails, SIEM |

**Authentication Factors:**

| Factor | Type | Examples |
|--------|------|----------|
| Something you know | Knowledge | Password, PIN, security questions |
| Something you have | Possession | Smart card, token, phone |
| Something you are | Inherence | Fingerprint, retina, face |
| Somewhere you are | Location | GPS, IP geolocation |
| Something you do | Behavior | Typing pattern, gait |

**Zero Trust Model:**
- "Never trust, always verify"
- Assume breach - verify everything
- Least privilege access
- Microsegmentation
- Continuous validation

**Zero Trust Principles:**
1. Verify explicitly (authenticate and authorize based on all data points)
2. Use least privilege access
3. Assume breach (minimize blast radius)

**Gap Analysis:**
- Compare current state to desired state
- Identify security deficiencies
- Prioritize remediation efforts

### 1.3 Change Management

**Why It Matters:**
- Uncontrolled changes = security vulnerabilities
- 80% of outages caused by changes
- Ensures changes are tested and approved

**Change Management Process:**
1. Request → 2. Review → 3. Approve → 4. Test → 5. Implement → 6. Document

**Key Elements:**
- Change Advisory Board (CAB)
- Impact assessment
- Rollback procedures
- Documentation requirements
- Version control

### 1.4 Cryptographic Concepts

**Symmetric vs Asymmetric:**

| Aspect | Symmetric | Asymmetric |
|--------|-----------|------------|
| Keys | Single shared key | Public/private key pair |
| Speed | Fast | Slow |
| Use Case | Bulk data encryption | Key exchange, digital signatures |
| Examples | AES, DES, 3DES | RSA, ECC, Diffie-Hellman |

**Common Algorithms:**

| Algorithm | Type | Key Size | Notes |
|-----------|------|----------|-------|
| AES | Symmetric | 128/192/256-bit | Current standard |
| RSA | Asymmetric | 2048/4096-bit | Key exchange, signatures |
| SHA-256 | Hashing | 256-bit output | Integrity verification |
| ECC | Asymmetric | 256-bit | Smaller keys, mobile-friendly |

**Hashing:**
- One-way function (cannot reverse)
- Fixed-length output regardless of input
- Same input = same hash (deterministic)
- Used for: Password storage, integrity verification

**Salting:**
- Random data added before hashing
- Prevents rainbow table attacks
- Each password gets unique salt

**Key Stretching:**
- Makes brute-force attacks slower
- Algorithms: PBKDF2, bcrypt, scrypt

**Digital Signatures:**
1. Hash the message
2. Encrypt hash with sender's private key
3. Recipient decrypts with sender's public key
4. Compares hashes to verify integrity and authenticity

**PKI Components:**

| Component | Function |
|-----------|----------|
| Certificate Authority (CA) | Issues and signs certificates |
| Registration Authority (RA) | Verifies identity before certificate issuance |
| Certificate Revocation List (CRL) | List of revoked certificates |
| OCSP | Real-time certificate status checking |

**Certificate Types:**
- DV (Domain Validation) - Basic, domain ownership only
- OV (Organization Validation) - Verifies organization
- EV (Extended Validation) - Highest trust, green bar

---

## Domain 2: Threats, Vulnerabilities & Mitigations (22%)

### 2.1 Threat Actors

| Actor Type | Resources | Sophistication | Motivation |
|------------|-----------|----------------|------------|
| Nation-State | Extensive | Very High | Espionage, warfare |
| Organized Crime | High | High | Financial gain |
| Hacktivist | Low-Medium | Medium | Political/ideological |
| Insider Threat | Varies | Varies | Revenge, financial, accidental |
| Unskilled Attacker | Low | Low | Curiosity, bragging rights |
| Shadow IT | Low | Low | Convenience, productivity |

**Threat Actor Attributes:**
- Internal vs External
- Resources/Funding level
- Sophistication/Capability
- Motivation (data exfiltration, disruption, financial, revenge, war)

### 2.2 Attack Vectors & Surfaces

**Message-Based Vectors:**
- Email (phishing, malicious attachments)
- SMS (smishing)
- Instant messaging
- Social media

**Physical Vectors:**
- USB drops (malicious devices)
- Tailgating/piggybacking
- Dumpster diving
- Shoulder surfing

**Network Vectors:**
- Wireless attacks (evil twin, rogue AP)
- Man-in-the-middle
- DNS poisoning
- ARP spoofing

**Supply Chain Vectors:**
- Compromised hardware/firmware
- Malicious software updates
- Third-party code vulnerabilities

### 2.3 Social Engineering

| Technique | Description |
|-----------|-------------|
| Phishing | Mass fraudulent emails |
| Spear Phishing | Targeted phishing at specific individuals |
| Whaling | Targeting executives |
| Vishing | Voice phishing (phone calls) |
| Smishing | SMS phishing |
| Pretexting | Creating false scenario to extract info |
| Baiting | Offering something enticing |
| Tailgating | Following authorized person through door |
| Watering Hole | Compromising frequently visited website |
| Typosquatting | Registering misspelled domains |

### 2.4 Malware Types

| Type | Behavior |
|------|----------|
| Virus | Attaches to files, requires user action |
| Worm | Self-replicating, spreads automatically |
| Trojan | Disguised as legitimate software |
| Ransomware | Encrypts files, demands payment |
| Spyware | Monitors user activity |
| Keylogger | Records keystrokes |
| Rootkit | Hides deep in OS, difficult to detect |
| Logic Bomb | Triggers on specific condition |
| RAT | Remote Access Trojan - backdoor access |
| Fileless Malware | Operates in memory, no file on disk |

### 2.5 Network Attacks

| Attack | Description | Mitigation |
|--------|-------------|------------|
| DoS/DDoS | Overwhelm resources | Rate limiting, CDN, filtering |
| Man-in-the-Middle | Intercept communications | TLS, certificate pinning |
| ARP Spoofing | Redirect traffic via ARP | Static ARP, DAI |
| DNS Poisoning | Corrupt DNS cache | DNSSEC, secure DNS |
| Replay Attack | Reuse captured credentials | Timestamps, nonces |
| Session Hijacking | Steal session tokens | Secure cookies, re-auth |

### 2.6 Application Attacks

| Attack | Description | Mitigation |
|--------|-------------|------------|
| SQL Injection | Inject SQL via input | Parameterized queries |
| XSS | Inject scripts in web pages | Input validation, encoding |
| CSRF | Trick user into unwanted action | CSRF tokens, SameSite cookies |
| Buffer Overflow | Exceed memory boundaries | Input validation, ASLR |
| Directory Traversal | Access unauthorized files | Input validation, chroot |
| LDAP Injection | Inject LDAP queries | Input validation |

### 2.7 Indicators of Compromise (IoC)

**Network Indicators:**
- Unusual outbound traffic
- Geographic anomalies
- Unexpected port usage
- DNS query anomalies

**Host Indicators:**
- Unexpected processes
- Registry changes
- File system changes
- Resource consumption spikes

**Account Indicators:**
- Account lockouts
- Impossible travel
- Concurrent sessions
- Privilege escalation

### 2.8 Mitigation Techniques

| Category | Techniques |
|----------|------------|
| Network | Segmentation, firewalls, IDS/IPS, VPN |
| Endpoint | EDR, antivirus, application control, patching |
| Identity | MFA, least privilege, PAM |
| Data | Encryption, DLP, backup |
| Application | WAF, input validation, secure coding |

---

## Domain 3: Security Architecture (18%)

### 3.1 Secure Network Architecture

**Network Segmentation:**
- VLANs separate broadcast domains
- DMZ for public-facing services
- Internal network isolation
- Microsegmentation for granular control

**Security Zones:**
```
Internet → Firewall → DMZ → Firewall → Internal Network
                        ↓
                    Web Server
                    Mail Server
```

**Network Security Devices:**

| Device | Function | Placement |
|--------|----------|-----------|
| Firewall | Filter traffic by rules | Network perimeter, internal segments |
| IDS | Detect suspicious activity | Behind firewall, internal segments |
| IPS | Detect and block threats | Inline, behind firewall |
| WAF | Protect web applications | In front of web servers |
| Proxy | Intermediate for requests | Between users and internet |
| NAC | Control network access | Network entry points |
| Load Balancer | Distribute traffic | In front of server farms |

**VPN Types:**

| Type | Use Case |
|------|----------|
| Site-to-Site | Connect branch offices |
| Remote Access | Individual user connections |
| Split Tunnel | Some traffic through VPN |
| Full Tunnel | All traffic through VPN |

### 3.2 Cloud Security

**Cloud Models:**

| Model | You Manage | Provider Manages |
|-------|------------|------------------|
| IaaS | OS, Apps, Data | Hardware, Virtualization |
| PaaS | Apps, Data | OS, Runtime, Hardware |
| SaaS | Data only | Everything else |

**Cloud Deployment:**
- Public - Shared infrastructure
- Private - Dedicated to one org
- Hybrid - Mix of public/private
- Community - Shared by similar orgs

**Cloud Security Concerns:**
- Data sovereignty/residency
- Shared responsibility model
- API security
- Identity federation
- Data encryption (at rest, in transit)

### 3.3 Identity and Access Management

**Authentication Methods:**

| Method | Description |
|--------|-------------|
| SSO | Single sign-on across applications |
| Federation | Trust across organizations (SAML, OIDC) |
| MFA | Multiple authentication factors |
| Passwordless | FIDO2, biometrics, magic links |

**Access Control Models:**

| Model | Description | Use Case |
|-------|-------------|----------|
| DAC | Owner controls access | File systems |
| MAC | Labels/clearances | Military/government |
| RBAC | Role-based permissions | Enterprise |
| ABAC | Attribute-based policies | Complex environments |
| Rule-based | Predefined rules | Firewalls |

**Privileged Access Management (PAM):**
- Just-in-time access
- Session recording
- Credential vaulting
- Least privilege enforcement

### 3.4 Data Security

**Data States:**
- At rest (stored)
- In transit (moving)
- In use (processing)

**Data Classification:**
- Public
- Internal/Private
- Confidential
- Restricted/Top Secret

**Data Loss Prevention (DLP):**
- Endpoint DLP (local devices)
- Network DLP (traffic inspection)
- Cloud DLP (SaaS/cloud storage)

**Data Protection Techniques:**

| Technique | Description |
|-----------|-------------|
| Encryption | Transform to unreadable |
| Tokenization | Replace with non-sensitive token |
| Masking | Hide portions of data |
| Anonymization | Remove identifying information |

### 3.5 Resilience and Recovery

**High Availability Concepts:**
- Redundancy (no single point of failure)
- Failover (automatic switch to backup)
- Load balancing (distribute across systems)
- Clustering (multiple systems as one)

**Backup Types:**

| Type | Description | Speed | Storage |
|------|-------------|-------|---------|
| Full | Complete copy | Slow | High |
| Incremental | Changes since last backup | Fast | Low |
| Differential | Changes since last full | Medium | Medium |

**Recovery Metrics:**
- RTO (Recovery Time Objective) - Max acceptable downtime
- RPO (Recovery Point Objective) - Max acceptable data loss
- MTTR (Mean Time to Recovery) - Average recovery time
- MTBF (Mean Time Between Failures) - Average uptime

---

## Domain 4: Security Operations (28%)

### 4.1 Security Monitoring

**SIEM (Security Information and Event Management):**
- Log aggregation
- Correlation and analysis
- Alerting and dashboards
- Compliance reporting

**Log Sources:**
- Firewalls, IDS/IPS
- Servers (OS, applications)
- Authentication systems
- Endpoints (EDR)
- Network devices
- Cloud services

**Key Metrics to Monitor:**
- Failed login attempts
- Privilege escalations
- Network traffic anomalies
- File integrity changes
- Configuration changes

### 4.2 Vulnerability Management

**Vulnerability Scanning:**
- Authenticated vs Unauthenticated
- Internal vs External
- Credentialed scans more thorough

**Vulnerability Assessment Process:**
1. Discovery (identify assets)
2. Scanning (find vulnerabilities)
3. Analysis (prioritize by risk)
4. Remediation (patch/mitigate)
5. Verification (confirm fixed)

**CVSS (Common Vulnerability Scoring System):**

| Score | Severity |
|-------|----------|
| 0.0 | None |
| 0.1-3.9 | Low |
| 4.0-6.9 | Medium |
| 7.0-8.9 | High |
| 9.0-10.0 | Critical |

### 4.3 Incident Response

**IR Phases:**
```
Preparation → Identification → Containment → Eradication → Recovery → Lessons Learned
```

| Phase | Activities |
|-------|------------|
| Preparation | Plans, tools, training, playbooks |
| Identification | Detect, alert, triage |
| Containment | Isolate, prevent spread |
| Eradication | Remove threat, patch |
| Recovery | Restore, verify, monitor |
| Lessons Learned | Document, improve |

**Incident Classification:**
- Severity levels (1-4 or Critical/High/Medium/Low)
- Categories (malware, unauthorized access, data breach, etc.)

**Communication:**
- Internal stakeholders
- Executive management
- Legal/compliance
- External (law enforcement, regulators, customers)

### 4.4 Digital Forensics

**Order of Volatility (collect first):**
1. CPU registers, cache
2. RAM
3. Network state
4. Running processes
5. Disk
6. Backups/archives
7. Physical configuration

**Chain of Custody:**
- Document who, what, when, where
- Maintain evidence integrity
- Use write blockers
- Hash verification

**Forensic Concepts:**
- Legal hold (preserve evidence)
- Imaging (bit-for-bit copy)
- Timeline analysis
- Artifact recovery

### 4.5 Automation and Orchestration

**SOAR (Security Orchestration, Automation, and Response):**
- Automate repetitive tasks
- Coordinate tools and workflows
- Standardize incident response
- Reduce response time

**Automation Use Cases:**
- Threat intelligence ingestion
- Alert enrichment
- Containment actions
- Ticket creation
- Reporting

---

## Domain 5: Security Program Management (20%)

### 5.1 Security Governance

**Governance Elements:**

| Element | Description |
|---------|-------------|
| Policies | High-level statements of intent |
| Standards | Mandatory requirements |
| Procedures | Step-by-step instructions |
| Guidelines | Recommended practices |
| Baselines | Minimum security configurations |

**Key Policies:**
- Acceptable Use Policy (AUP)
- Information Security Policy
- Data Classification Policy
- Incident Response Policy
- Business Continuity Policy

**Roles and Responsibilities:**

| Role | Responsibility |
|------|----------------|
| CISO | Overall security program |
| Security Analyst | Monitor, investigate, respond |
| Security Engineer | Design, implement controls |
| Data Owner | Classify, protect data assets |
| Data Custodian | Day-to-day data management |

### 5.2 Risk Management

**Risk Formula:**
```
Risk = Threat × Vulnerability × Impact
```

**Risk Assessment Types:**

| Type | Approach |
|------|----------|
| Qualitative | High/Medium/Low ratings |
| Quantitative | Dollar values (ALE, SLE, ARO) |

**Quantitative Formulas:**
- SLE (Single Loss Expectancy) = Asset Value × Exposure Factor
- ALE (Annual Loss Expectancy) = SLE × ARO (Annual Rate of Occurrence)

**Risk Treatment Options:**
1. Accept - Acknowledge and monitor
2. Avoid - Eliminate the risk source
3. Transfer - Insurance, third party
4. Mitigate - Implement controls

**Risk Appetite vs Tolerance:**
- Appetite: Level of risk org is willing to accept
- Tolerance: Acceptable variation from appetite

### 5.3 Third-Party Risk

**Due Diligence Activities:**
- Security questionnaires
- Audit reports (SOC 2, ISO 27001)
- Penetration test results
- Financial stability
- Business continuity plans

**Contract Elements:**
- SLA (Service Level Agreement)
- NDA (Non-Disclosure Agreement)
- Right to audit
- Data handling requirements
- Incident notification requirements

**Vendor Risk Assessment:**
- Access to sensitive data?
- Integration with systems?
- Criticality to operations?
- Geographic location?
- Subcontractor usage?

### 5.4 Compliance

**Key Regulations/Frameworks:**

| Framework | Focus |
|-----------|-------|
| GDPR | EU data privacy |
| HIPAA | US healthcare data |
| PCI-DSS | Payment card data |
| SOX | Financial reporting |
| NIST CSF | Cybersecurity framework |
| ISO 27001 | Information security management |
| SOC 2 | Service organization controls |

**Compliance Activities:**
- Gap assessments
- Policy development
- Control implementation
- Audit preparation
- Evidence collection
- Remediation tracking

### 5.5 Audits and Assessments

**Audit Types:**

| Type | Performed By |
|------|--------------|
| Internal | Organization's own team |
| External | Third-party auditors |
| Regulatory | Government agencies |

**Assessment Types:**
- Vulnerability assessment
- Penetration testing
- Security audit
- Compliance assessment
- Risk assessment

### 5.6 Security Awareness

**Training Topics:**
- Phishing recognition
- Password security
- Social engineering
- Data handling
- Incident reporting
- Clean desk policy
- Physical security

**Training Methods:**
- Computer-based training (CBT)
- Simulated phishing
- In-person sessions
- Gamification
- Lunch and learns

---

## Key Acronyms

| Acronym | Meaning |
|---------|---------|
| AAA | Authentication, Authorization, Accounting |
| ACL | Access Control List |
| AES | Advanced Encryption Standard |
| APT | Advanced Persistent Threat |
| CA | Certificate Authority |
| CIA | Confidentiality, Integrity, Availability |
| CVSS | Common Vulnerability Scoring System |
| DLP | Data Loss Prevention |
| DMZ | Demilitarized Zone |
| EDR | Endpoint Detection and Response |
| IDS | Intrusion Detection System |
| IPS | Intrusion Prevention System |
| MFA | Multi-Factor Authentication |
| NAC | Network Access Control |
| NIST | National Institute of Standards and Technology |
| PAM | Privileged Access Management |
| PKI | Public Key Infrastructure |
| RBAC | Role-Based Access Control |
| RTO | Recovery Time Objective |
| RPO | Recovery Point Objective |
| SIEM | Security Information and Event Management |
| SOAR | Security Orchestration, Automation, and Response |
| SOC | Security Operations Center |
| SSO | Single Sign-On |
| TLS | Transport Layer Security |
| VPN | Virtual Private Network |
| WAF | Web Application Firewall |
| XSS | Cross-Site Scripting |

---

## Common Ports

| Port | Service | Protocol |
|------|---------|----------|
| 20/21 | FTP | TCP |
| 22 | SSH/SFTP | TCP |
| 23 | Telnet | TCP |
| 25 | SMTP | TCP |
| 53 | DNS | TCP/UDP |
| 67/68 | DHCP | UDP |
| 80 | HTTP | TCP |
| 110 | POP3 | TCP |
| 143 | IMAP | TCP |
| 443 | HTTPS | TCP |
| 445 | SMB | TCP |
| 389 | LDAP | TCP |
| 636 | LDAPS | TCP |
| 1433 | MSSQL | TCP |
| 3306 | MySQL | TCP |
| 3389 | RDP | TCP |

---

## Study Tips

1. **Focus on Domain 4** - 28% of the exam
2. **Understand "why"** - Know why controls exist, not just what they are
3. **Practice scenarios** - PBQs test application, not memorization
4. **Use acronyms wisely** - Know them but understand the concepts
5. **Lab work** - Hands-on practice reinforces learning
6. **Take practice exams** - Time yourself and review wrong answers

---

## References

- [CompTIA Security+ SY0-701 Exam Objectives](https://www.comptia.org/certifications/security)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CIS Controls](https://www.cisecurity.org/controls)
