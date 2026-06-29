# Microsoft AZ-500: Azure Security Technologies

*(Note: Microsoft does not have an "SC-500" exam; the primary expert-level security engineering and architecture certificates are **AZ-500** for Cloud Security Engineers and **SC-100** for Cybersecurity Architects. These notes target the **AZ-500**: Microsoft Azure Security Technologies certification.)*

---

## 1. Manage Identity and Access (Microsoft Entra ID)

### Hybrid Identity & Access
*   **Microsoft Entra Connect:** Synchronizes users, groups, and password hashes from on-premises Active Directory Domain Services (AD DS) to cloud-based Microsoft Entra ID.
*   **Active Directory Federation Services (AD FS):** Enables federated authentication where local domain controllers perform the credentials check directly.

### Advanced Authentication & Protection
*   **Microsoft Entra ID Protection:** Uses ML to analyze sign-in risks (impossible travel, leaked credentials) and enforces automatic self-remediation (like MFA prompt or password reset).
*   **Privileged Identity Management (PIM):**
    *   Enforces Just-in-Time (JIT) access.
    *   Enables time-bounded administrative roles (e.g., active for only 2 hours).
    *   Requires explicit manager approval or ticket numbers for activation.
    *   Generates full audit trails.

---

## 2. Secure Infrastructure

### Azure Virtual Networks (VNet) Security
*   **Network Security Groups (NSGs):** Layer 4 stateful packet filters applied at the subnet or Network Interface (NIC) level.
*   **Application Security Groups (ASGs):** Allows grouping VMs under logical tags (e.g., `ASG-Web`, `ASG-DB`) and referencing them in NSG rules, making firewall rule structures independent of dynamic IP changes.
*   **User Defined Routes (UDRs):** Custom routing tables override default Azure routes, routing subnet egress traffic directly through a Central Virtual Firewall Appliance (NVA).

### Host & Platform Security
*   **Azure Bastion:** Managed PaaS offering secure RDP/SSH terminal access directly within the Azure Portal over SSL (Port 443), removing the need for public IP addresses on VMs.
*   **Just-in-Time VM Access:** Restricts inbound management traffic (RDP/SSH) by configuring NSG rules to open ports *only* when requested, approved, and for a short window.
*   **Disk Encryption:**
    *   *Azure Disk Encryption (ADE):* DM-Crypt (Linux) and BitLocker (Windows) to encrypt VM OS and data disks. Integrated directly with Azure Key Vault.

---

## 3. Secure Data and Applications

### Key Vault Management
*   **Azure Key Vault:** Centralized, secure storage for secrets (passwords, connection strings), keys (encryption keys), and certificates.
    *   *Soft Delete & Purge Protection:* Mandatory guards preventing immediate deletion of key vaults or secrets by rogue admins, retaining deleted vaults in a recycle bin for a set period.

### Database Security
*   **Always Encrypted:** Client-side database encryption technique where database engine processes data without seeing the decrypted plaintext.
*   **Microsoft Defender for SQL:** Performs vulnerability assessments and anomalous database activities audits.
*   **Dynamic Data Masking (DDM):** Limits sensitive data exposure by masking it to non-privileged users (e.g., masking credit card column outputs as `XXXX-XXXX-XXXX-1234`).

---

## 4. Security Operations

### Security Management with Defender for Cloud
*   **Microsoft Defender for Cloud:** Cloud Security Posture Management (CSPM) and Cloud Workload Protection (CWPP) dashboard.
    *   Calculates **Secure Score** based on cloud configurations against benchmarks (e.g., ISO 27001, CIS).
    *   Auto-detects missing configurations (like unprotected ports or unencrypted databases).

### Threat Detection with Microsoft Sentinel
*   **Microsoft Sentinel:** Native cloud SIEM (Security Information and Event Management) and SOAR (Security Orchestration, Automation, and Response).
    *   Aggregates event logs from multiple clouds and local nodes.
    *   Uses **KQL (Kusto Query Language)** to query events and build automated detection analytics.
    *   Triggers **Playbooks (Logic Apps)** to isolate resources or alert security centers.
