# Security+ SY0-701 Quick Reference

## Exam Day Cheat Sheet

### Control Types - REMEMBER: "PDCDCD"
- **P**reventive - Stop before it happens
- **D**etective - Find during/after
- **C**orrective - Fix after incident
- **D**eterrent - Discourage attackers
- **C**ompensating - Alternative control
- **D**irective - Policy/procedure

### Control Categories - "TMOP"
- **T**echnical - Technology-based
- **M**anagerial - Administrative/policy
- **O**perational - Day-to-day procedures
- **P**hysical - Tangible protections

---

## Cryptography Quick Facts

### Symmetric Algorithms (FAST, shared key)
| Algorithm | Status |
|-----------|--------|
| AES | ✅ Current standard (128/192/256-bit) |
| 3DES | ⚠️ Legacy, being phased out |
| DES | ❌ Deprecated (56-bit too weak) |
| RC4 | ❌ Deprecated |
| Blowfish | ⚠️ Legacy |

### Asymmetric Algorithms (SLOW, key pairs)
| Algorithm | Use |
|-----------|-----|
| RSA | Encryption, digital signatures |
| ECC | Mobile, IoT (smaller keys) |
| Diffie-Hellman | Key exchange only |
| DSA | Digital signatures only |

### Hashing Algorithms
| Algorithm | Output | Status |
|-----------|--------|--------|
| MD5 | 128-bit | ❌ Deprecated |
| SHA-1 | 160-bit | ❌ Deprecated |
| SHA-256 | 256-bit | ✅ Current |
| SHA-3 | Variable | ✅ Current |

### Key Concepts
- **Hashing** = One-way, integrity
- **Encryption** = Two-way, confidentiality
- **Salt** = Random data + password before hashing
- **Key Stretching** = PBKDF2, bcrypt, scrypt (slow down brute force)

---

## Threat Actors Matrix

| Actor | Internal/External | Resources | Sophistication |
|-------|-------------------|-----------|----------------|
| Nation-State | External | Very High | Very High |
| Organized Crime | External | High | High |
| Hacktivist | External | Low-Med | Medium |
| Insider | Internal | Low-High | Varies |
| Script Kiddie | External | Low | Low |

### Motivation Quick Guide
- **Nation-State**: Espionage, warfare, disruption
- **Organized Crime**: Financial gain
- **Hacktivist**: Political/ideological
- **Insider**: Revenge, financial, accidental
- **Script Kiddie**: Curiosity, bragging

---

## Social Engineering Types

| Attack | Vector | Target |
|--------|--------|--------|
| Phishing | Email | Mass targets |
| Spear Phishing | Email | Specific person |
| Whaling | Email | Executives |
| Vishing | Phone | Anyone |
| Smishing | SMS | Anyone |
| Pretexting | Any | Targeted |
| Baiting | Physical | Curious users |
| Tailgating | Physical | Secure areas |
| Watering Hole | Website | Specific group |

---

## Attack Types Quick Reference

### Web Application Attacks
| Attack | Input | Target |
|--------|-------|--------|
| SQL Injection | ' OR 1=1-- | Database |
| XSS | `<script>` | Browser |
| CSRF | Hidden requests | User session |
| XXE | XML entities | XML parser |
| SSRF | Internal URLs | Server |

### Network Attacks
| Attack | Layer | Mitigation |
|--------|-------|------------|
| ARP Spoofing | 2 | DAI, static ARP |
| VLAN Hopping | 2 | Proper config |
| DNS Poisoning | 7 | DNSSEC |
| DDoS | 3-7 | Rate limiting, CDN |
| Man-in-the-Middle | 2-7 | TLS, cert pinning |

### Password Attacks
| Attack | Method |
|--------|--------|
| Brute Force | Try all combinations |
| Dictionary | Common words |
| Rainbow Table | Pre-computed hashes |
| Spraying | One password, many accounts |
| Credential Stuffing | Stolen creds, other sites |

---

## Authentication Factors

| Factor | "Something you..." | Examples |
|--------|-------------------|----------|
| Type 1 | Know | Password, PIN |
| Type 2 | Have | Token, smart card, phone |
| Type 3 | Are | Fingerprint, face, retina |
| Type 4 | Are (location) | GPS, IP address |
| Type 5 | Do | Typing pattern, gait |

**MFA** = 2+ different factor types (password + token = MFA ✅, password + PIN = NOT MFA ❌)

---

## Access Control Models

| Model | Description | Use Case |
|-------|-------------|----------|
| DAC | Owner sets permissions | File systems |
| MAC | Labels/clearances | Military |
| RBAC | Based on job role | Enterprise |
| ABAC | Based on attributes | Complex policies |
| Rule-based | If-then rules | Firewalls |

---

## Network Security Devices

| Device | Function | Inline? |
|--------|----------|---------|
| Firewall | Filter traffic | Yes |
| IDS | Detect only | No (passive) |
| IPS | Detect + Block | Yes |
| WAF | Protect web apps | Yes |
| Proxy | Intermediate requests | Yes |
| NAC | Control access | Yes |

### Firewall Types
- **Packet Filtering** - Layer 3-4, stateless
- **Stateful** - Tracks connections
- **Application** - Layer 7, content inspection
- **NGFW** - All above + threat intelligence

---

## Incident Response Phases

```
P → I → C → E → R → L
Preparation → Identification → Containment → Eradication → Recovery → Lessons Learned
```

| Phase | Key Activities |
|-------|----------------|
| Preparation | Plans, tools, training |
| Identification | Detect, analyze, triage |
| Containment | Isolate, stop spread |
| Eradication | Remove threat, patch |
| Recovery | Restore, verify |
| Lessons Learned | Document, improve |

---

## Forensics Order of Volatility

**Collect FIRST (most volatile):**
1. CPU registers/cache
2. RAM
3. Network state
4. Running processes
5. Disk
6. Backups
7. Physical configuration

---

## Backup Types

| Type | What's Backed Up | Restore Speed |
|------|------------------|---------------|
| Full | Everything | Fastest |
| Incremental | Since last ANY backup | Slowest |
| Differential | Since last FULL backup | Medium |

---

## Recovery Metrics

| Metric | Question Answered |
|--------|-------------------|
| RTO | How long can we be down? |
| RPO | How much data can we lose? |
| MTTR | How long to recover on average? |
| MTBF | How long between failures? |

---

## Cloud Models - Who Manages What?

| Model | You Manage | Provider Manages |
|-------|------------|------------------|
| On-Prem | Everything | Nothing |
| IaaS | OS → up | Hardware/Virtualization |
| PaaS | Apps/Data | OS/Runtime |
| SaaS | Data config | Everything |

---

## Risk Management

### Risk Formula
```
Risk = Threat × Vulnerability × Impact
```

### Quantitative Formulas
- **SLE** = Asset Value × Exposure Factor
- **ALE** = SLE × ARO

### Risk Responses - "ATAM"
- **A**ccept - Acknowledge the risk
- **T**ransfer - Insurance/third party
- **A**void - Eliminate the source
- **M**itigate - Implement controls

---

## Compliance Frameworks

| Framework | Focus | Type |
|-----------|-------|------|
| GDPR | EU Privacy | Regulation |
| HIPAA | Healthcare | Regulation |
| PCI-DSS | Payment Cards | Standard |
| SOX | Financial | Regulation |
| NIST CSF | Cybersecurity | Framework |
| ISO 27001 | InfoSec | Standard |
| SOC 2 | Service Orgs | Report |

---

## Common Ports - MEMORIZE THESE

| Port | Service | Secure Alternative |
|------|---------|-------------------|
| 21 | FTP | 22 (SFTP) |
| 22 | SSH | - |
| 23 | Telnet | 22 (SSH) |
| 25 | SMTP | 465/587 (SMTPS) |
| 53 | DNS | 853 (DoT) |
| 80 | HTTP | 443 (HTTPS) |
| 110 | POP3 | 995 (POP3S) |
| 143 | IMAP | 993 (IMAPS) |
| 389 | LDAP | 636 (LDAPS) |
| 443 | HTTPS | - |
| 445 | SMB | - |
| 1433 | MSSQL | - |
| 3306 | MySQL | - |
| 3389 | RDP | - |

---

## Zero Trust Principles

1. **Never trust, always verify**
2. **Assume breach**
3. **Verify explicitly**
4. **Least privilege access**
5. **Microsegmentation**

---

## PKI Components

| Component | Function |
|-----------|----------|
| CA | Issues certificates |
| RA | Verifies identity |
| CRL | Lists revoked certs |
| OCSP | Real-time cert status |

### Certificate Types
- **DV** = Domain only
- **OV** = Organization verified
- **EV** = Extended validation (highest)

---

## SIEM vs SOAR

| SIEM | SOAR |
|------|------|
| Collect logs | Automate response |
| Correlate events | Orchestrate tools |
| Alert | Playbooks |
| Report | Reduce response time |

---

## Last-Minute Tips

1. **Read questions carefully** - "BEST" vs "FIRST" vs "MOST"
2. **Eliminate wrong answers** - Usually 2 obviously wrong
3. **Scenario context matters** - Same concept, different answers based on scenario
4. **Don't overthink** - First instinct often correct
5. **Flag and return** - Don't get stuck on PBQs
6. **Time management** - ~1 min/question average
