# Domain 2: Threats, Vulnerabilities, and Mitigations (SY0-701)

This section covers **22%** of the CompTIA Security+ SY0-701 exam, focusing on identifying cyber threats, analyzing vulnerabilities, and applying practical mitigation strategies.

---

## 1. Threat Actors and Threat Intelligence

Understanding *who* is attacking and *why* helps defenders prioritize their defenses.

### Threat Actor Types

| Actor Type | Motivation | Sophistication / Resources | Example Targets |
| :--- | :--- | :--- | :--- |
| **Nation-State / APT** | Espionage, political disruption, warfare | Extremely high; zero-day capabilities | Power grids, defense contractors, government |
| **Organized Crime** | Financial gain | High; well-funded ransomware operations | Banks, healthcare, large enterprises |
| **Hacktivist** | Ideology, political messaging | Varies; usually relies on DDoS / defacement | Corporations with conflicting views, governments |
| **Insider Threat** | Revenge, financial gain, or accidental | Varies; high access privileges | Stolen IP, deleted databases, exposed S3 buckets |
| **Script Kiddie** | Notoriety, curiosity | Low; uses pre-packaged exploit tools | Random vulnerable systems, gaming networks |

### Threat Intelligence Sources
- **OSINT (Open-Source Intelligence):** Publicly available data (e.g., social media, public forums, WHOIS records).
- **Dark Web / Deep Web:** Monitoring underground forums for leaked credentials or planned attacks.
- **Indicators of Compromise (IoCs):** Artifacts observed on a network that indicate an intrusion (e.g., malware hashes, malicious IPs, known C2 domains).
- **STIX/TAXII:** 
  - **STIX** (Structured Threat Information eXpression): A language/format for sharing threat intelligence.
  - **TAXII** (Trusted Automated eXchange of Indicator Information): The transport mechanism for STIX data.

---

## 2. Threat Vectors and Attack Types

A **threat vector** is the path or means by which an attacker gains access to a computer or network server.

### Social Engineering
Exploiting human psychology rather than technical vulnerabilities.
- **Phishing:** Fraudulent emails designed to steal credentials.
- **Spear Phishing:** Targeted phishing at a specific individual or role.
- **Whaling:** Targeted phishing at high-level executives (CEOs, CFOs).
- **Vishing / Smishing:** Phishing via Voice (phone calls) or SMS (text messages).
- **Baiting:** Leaving a malware-infected physical device (like a USB drive) for someone to find and plug in.
- **Principles of Influence:** Authority, Urgency, Consensus/Social Proof, Scarcity, Familiarity.

### Malware Types
- **Ransomware:** Encrypts user data and demands payment for the decryption key.
- **Trojans:** Malicious software disguised as legitimate software.
- **Worms:** Self-replicating malware that spreads across networks without user intervention.
- **Rootkits:** Software designed to hide the existence of certain processes or programs from normal methods of detection (operates at the OS/Kernel level).
- **Keyloggers:** Records keystrokes to steal passwords and sensitive data.
- **Fileless Malware:** Operates entirely in memory (RAM), leaving no footprint on the hard drive, making it harder for traditional antivirus to detect.

### Network and Application Attacks
- **DDoS (Distributed Denial of Service):** Overwhelming a system with traffic from multiple sources to make it unavailable.
- **Man-in-the-Middle (MitM) / On-Path:** Intercepting communication between two parties to steal or alter data.
- **Cross-Site Scripting (XSS):** Injecting malicious scripts into trusted websites viewed by other users.
- **SQL Injection (SQLi):** Injecting malicious SQL statements into a database query to manipulate or steal data.

---

## 3. Vulnerability Identification and Management

### Types of Vulnerabilities
1. **Software/Application:** Unpatched software, buffer overflows, memory leaks.
2. **Hardware:** Firmware vulnerabilities, supply chain compromises.
3. **Configuration:** Default passwords, open ports, misconfigured cloud storage (e.g., public AWS S3 buckets).
4. **User/Process:** Lack of security awareness, weak passwords, missing incident response plans.

### Scanning and Assessment
- **Vulnerability Scanning:** Automated process of identifying known vulnerabilities (non-intrusive).
- **Penetration Testing:** Authorized simulated attack on a computer system, performed to evaluate the security of the system (intrusive).
  - *Phases:* Planning & Reconnaissance $\rightarrow$ Scanning $\rightarrow$ Exploitation $\rightarrow$ Post-Exploitation $\rightarrow$ Reporting.
- **Bug Bounties:** Crowdsourced security testing where ethical hackers are rewarded for finding and reporting bugs.

---

## 4. Mitigation Strategies

- **Patch Management:** Regularly updating software and OS to fix known vulnerabilities.
- **Principle of Least Privilege:** Giving users only the access they absolutely need to perform their jobs.
- **Defense in Depth:** Layering security controls (e.g., Firewall + IPS + EDR + MFA).
- **Security Awareness Training:** Educating employees to recognize and report social engineering attacks.
- **Network Segmentation:** Dividing a network into smaller segments to limit the blast radius if an attacker breaches the perimeter.
