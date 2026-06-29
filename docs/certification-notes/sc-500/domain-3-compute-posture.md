# <img src="../../assets/images/azure-logo.svg" width="36" height="36" style="vertical-align: middle; margin-right: 10px;"> SC-500 Domain 3: Secure Compute Workloads and Posture

This domain details compute hardening (bastions, VM endpoints), cryptographic key vaults, and posture management tools.

---

## 1. Compute & Endpoint Hardening

### 1.1 Secure VM Access with Azure Bastion
Azure Bastion provides secure, browser-based administrative terminal sessions (RDP/SSH) directly inside the Azure Portal over HTTPS (Port 443).
*   Eliminates the need for public IP addresses on target VMs.
*   Bypasses local port exposures, routing traffic securely via VNet IPs.

### 1.2 Just-in-Time (JIT) VM Access
JIT VM access locks down inbound management traffic (RDP/SSH) by configuring Network Security Group (NSG) rules.
*   Administrative ports are kept closed by default.
*   Users request access via Entra ID, and rules are opened only upon approval for a limited duration (e.g. 3 hours).

---

## 2. Azure Key Vault Hardening

Azure Key Vault provides secure storage for secrets, cryptographic keys, and certificates.

### 2.1 Soft Delete
Enables recovery of deleted vaults and vault objects (keys, secrets) for a retention window (default 90 days).

### 2.2 Purge Protection
Purge protection prevents immediate, permanent deletion of key vaults or vault objects during the retention window. Even Subscription Owners cannot bypass this lock, preventing destructive ransomware actions.

---

## 3. Posture Auditing & Threat Protection

### 3.1 Microsoft Defender for Cloud
Defender for Cloud provides Cloud Security Posture Management (CSPM) and Cloud Workload Protection (CWPP).
*   **Secure Score:** Represents your organization's security posture. Points are earned by remediating configurations (such as closing public ports, turning on encryption, or enabling MFA).
*   **Regulatory Compliance:** Benchmarks your subscription configuration against standards (e.g., CIS Benchmarks, ISO 27001).

### 3.2 Microsoft Sentinel Integration
Microsoft Sentinel operates as a cloud-native SIEM/SOAR system.
*   **Data Connectors:** Ingests log metrics from Entra ID, Azure Monitor, and firewalls.
*   **KQL Analytics:** Runs automated search queries to spot threats.
*   **SOAR Playbooks:** Triggers Logic Apps to auto-isolate resources or prompt administrators when alerts fire.
