# Google Cybersecurity Professional Certificate

This document covers core domains, tools, and technical competencies taught throughout the Google Cybersecurity Professional Certificate.

---

## 1. Foundations of Cybersecurity

### Core Security Principles
*   **CIA Triad:**
    *   **Confidentiality:** Ensuring only authorized entities can access data (achieved via Encryption, Access Controls, MFA).
    *   **Integrity:** Ensuring data has not been modified or tampered with (achieved via Hashing, Digital Signatures, Checksums).
    *   **Availability:** Ensuring systems and data are reachable by authorized users when needed (achieved via Redundancy, Backups, DDoS mitigations).
*   **Defense in Depth:** Implementing multiple layers of security controls (physical, technical, administrative) so if one fails, others protect the asset.
*   **Least Privilege:** Giving users and processes only the absolute minimum permissions required to perform their jobs.

---

## 2. Linux and SQL for Security

### Essential Linux Command Line Tools
Security analysts use the Linux CLI to inspect logs, manage system permissions, and audit configurations.
- `ls -la`: Lists all directory files with permissions, owner, and group details.
- `chmod`: Modifies file permissions (e.g., `chmod 600 config.txt` sets read/write only for owner).
- `chown`: Changes file ownership.
- `grep`: Searches files for specific text strings (e.g., `grep "Failed password" /var/log/auth.log` to audit brute force).
- `find`: Locates files based on criteria.
- `sudo`: Executes commands with administrative (root) privileges.

### SQL for Security Analysis
SQL queries are used to query databases containing access logs, employee directories, or asset registers.

**Querying Access Logs:**
```sql
SELECT username, login_time, ip_address, status 
FROM login_attempts 
WHERE status = 'Failed' AND login_time >= '2026-06-01';
```

---

## 3. Assets, Networks, and Threats

### Networking Basics
*   **OSI Model:**
    1. Physical, 2. Data Link, 3. Network (IP, ICMP), 4. Transport (TCP, UDP), 5. Session, 6. Presentation, 7. Application (HTTP, DNS, SSH).
*   **TCP/IP Handshake:** SYN -> SYN-ACK -> ACK.
*   **Protocols:**
    - **DNS (53):** Resolves domain names to IP addresses.
    - **SSH (22):** Secure remote shell access.
    - **HTTPS (443):** Secure web browsing via TLS.

### Defensive Tools
*   **SIEM (Security Information and Event Management):** Aggregates logs from networks, servers, and security appliances to correlate events and detect anomalies.
*   **IDS/IPS:**
    - *IDS:* Intrusion Detection System (audits and alerts on threat signatures).
    - *IPS:* Intrusion Prevention System (actively blocks/drops malicious packets).
*   **Firewalls:** Filters traffic based on IP addresses, ports, and protocols.

---

## 4. Python Programming for Security

Python is used to automate repetitive tasks like log parsing, IP scanning, or file checking.

**Automated Log Parsing Script:**
```python
def check_failed_logins(log_file):
    with open(log_file, 'r') as file:
        for line in file:
            if "Failed login" in line:
                parts = line.split()
                ip = parts[-1]  # Extract IP address
                print(f"Alert: Failed login attempt detected from IP: {ip}")

# Run analysis
check_failed_logins("/var/log/secure")
```

---

## 5. Threat Detection and Incident Response

### Incident Response Lifecycle (NIST)
1.  **Preparation:** Establish security policies, incident response plans, and deployment of detection tools.
2.  **Detection and Analysis:** Identify potential incidents and analyze scope, vectors, and baseline impact.
3.  **Containment, Eradication, and Recovery:** Limit the attack blast radius, remove threats (delete malware, patch vulnerabilities), and restore clean system state.
4.  **Post-Incident Activity:** Document lessons learned to improve security postures and plans.
