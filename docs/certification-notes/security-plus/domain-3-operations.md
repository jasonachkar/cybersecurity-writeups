# Domain 4: Security Operations (SY0-701)

This section covers **28%** of the CompTIA Security+ SY0-701 exam, making it the largest domain. It focuses on the practical, day-to-day tasks required to maintain an organization's security posture, monitor for threats, and respond to incidents.

---

## 1. Security Alerting and Monitoring

Monitoring is critical for identifying suspicious behavior before it becomes a full-blown breach.

### SIEM (Security Information and Event Management)
A central system that aggregates, correlates, and analyzes log data from across the enterprise (e.g., firewalls, endpoints, servers).
- **Log Aggregation:** Centralizing logs into one searchable location.
- **Correlation:** Linking seemingly unrelated events to detect a larger attack pattern (e.g., 5 failed logins on a VPN followed by a successful login from a new country).
- **Dashboards & Alerts:** Providing visual representations of security health and triggering alerts when thresholds are crossed.

### Endpoint Security
- **EDR (Endpoint Detection and Response):** Goes beyond traditional antivirus by continuously monitoring endpoint activities, recording telemetry, and providing tools to actively respond to threats (e.g., isolating a compromised machine).
- **XDR (Extended Detection and Response):** Evolves EDR by integrating telemetry from the network, cloud, and endpoints into a unified threat detection and response platform.

---

## 2. Vulnerability Management

Vulnerability management is the cyclical practice of identifying, classifying, prioritizing, remediating, and mitigating software vulnerabilities.

### The Vulnerability Management Lifecycle
1. **Discover:** Identify all assets on the network.
2. **Prioritize:** Determine which assets are most critical.
3. **Assess:** Scan for vulnerabilities.
4. **Report:** Generate actionable metrics and remediation plans.
5. **Remediate:** Patch, reconfigure, or implement compensatory controls.
6. **Verify:** Rescan to ensure the vulnerability is resolved.

### CVSS (Common Vulnerability Scoring System)
An open framework for communicating the characteristics and severity of software vulnerabilities. Scores range from 0.0 to 10.0.
- **Low:** 0.1 - 3.9
- **Medium:** 4.0 - 6.9
- **High:** 7.0 - 8.9
- **Critical:** 9.0 - 10.0

---

## 3. Incident Response Activities

When a breach occurs, a structured response is required to minimize damage.

### The Incident Response Process (PICERL)
1. **Preparation:** Having a policy, building an Incident Response Plan (IRP), assembling the CSIRT (Computer Security Incident Response Team), and running tabletop exercises.
2. **Identification:** Detecting the incident and determining its scope.
3. **Containment:** Stopping the bleeding. Can be *isolation* (disconnecting the machine from the network) or *segmentation*. 
4. **Eradication:** Removing the root cause (e.g., deleting malware, patching the exploited vulnerability).
5. **Recovery:** Restoring systems to normal operation and monitoring them closely to ensure the attacker is truly gone.
6. **Lessons Learned:** A post-incident review to determine what went right, what went wrong, and how to improve the IRP for next time.

### Digital Forensics
- **Order of Volatility:** When collecting evidence, always capture the most volatile data first.
  1. CPU Cache / Registers
  2. Routing tables, ARP cache, process tables, kernel statistics
  3. RAM (System Memory)
  4. Temporary File Systems / Swap space
  5. Hard Disks (Data at rest)
- **Chain of Custody:** A chronological paper trail that documents who collected, handled, transferred, and analyzed digital evidence to ensure it remains admissible in court.

---

## 4. Identity and Access Management (IAM)

Controlling who gets access to what.

### Authentication vs. Authorization
- **Authentication:** Proving *who* you are (e.g., entering a password).
- **Authorization:** Determining *what* you are allowed to do once authenticated (e.g., read-only access to a database).

### Authentication Factors
- **Something you know:** Password, PIN, security question.
- **Something you have:** Smart card, hardware token (YubiKey), smartphone (Authenticator app).
- **Something you are:** Biometrics (fingerprint, retina scan).
- **Somewhere you are:** Geolocation mapping (e.g., blocking logins from outside the home country).

### Access Control Models
- **RBAC (Role-Based Access Control):** Access is based on the user's job function or role (e.g., all HR employees get access to the HR folder). The most common model in enterprise environments.
- **MAC (Mandatory Access Control):** Access is based on strict clearance levels and data labels (e.g., Top Secret). Common in military and government.
- **DAC (Discretionary Access Control):** The creator/owner of a file decides who has access to it. Common in consumer operating systems.
- **ABAC (Attribute-Based Access Control):** Access is evaluated dynamically based on policies that evaluate attributes (e.g., "Allow access if User is Manager AND Time is 9 AM-5 PM AND Device is Company-Issued").

---

## 5. Automation and Orchestration
- **SOAR (Security Orchestration, Automation, and Response):** A stack of compatible software programs that allows an organization to collect data about security threats and respond to low-level security events automatically (e.g., automatically blocking a malicious IP address on the firewall when the SIEM detects a brute force attack).
- **Playbooks / Runbooks:** Standard operating procedures that dictate exactly how to respond to specific types of incidents. Playbooks can be partially or fully automated using SOAR.
