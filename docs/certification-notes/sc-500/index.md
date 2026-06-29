# Microsoft SC-500: Implementing End-to-End Security Controls for Cloud and AI Workloads

Microsoft's **SC-500: Cloud and AI Security Engineer Associate** exam entered beta in May 2026 and officially launches in July 2026. It serves as the official successor to the **AZ-500 (Azure Security Engineer Associate)** exam, which retires on August 31, 2026.

Unlike its predecessor, the SC-500 features a heavy emphasis on **securing AI pipelines, generative models, and agent architectures**, alongside traditional cloud infrastructure controls.

---

## 1. Manage Identity, Access, and Governance

### Entra ID & Access Infrastructure
*   **Workload Identities:** Security configurations (managed identities, service principals) to allow non-human entities (applications, VMs, AI agents) to securely authenticate to Azure resources without managing credentials.
*   **Conditional Access Policies:** Implements zero-trust security control points based on context (user, location, device health, sign-in risk).
*   **Privileged Identity Management (PIM):** Enforces Just-in-Time (JIT) access for high-privilege roles, requiring approvals, activation time bounds (e.g., 2 hours), and MFA.

### Governance
*   **Microsoft Entra ID Governance:** Automates access lifecycles using access reviews and entitlement management (Access Packages).
*   **Azure RBAC & Policies:** Granular cloud resource access controls combined with Azure Policy rules enforcing compliance.

---

## 2. Secure Storage, Databases, and Networking

### Data Layer Security
*   **Azure Storage Hardening:** Use of Private Endpoints, Shared Access Signatures (SAS) with expiration limits, and Microsoft Defender for Storage (malware scanning on upload).
*   **SQL Database Defenses:** Enforces *Always Encrypted* client-side cryptography, Dynamic Data Masking (DDM), and Microsoft Defender for SQL.

### Cloud Networking Hardening
*   **Private Link & Private Endpoints:** Exposes Azure PaaS services (SQL, Storage, Azure OpenAI) over a private IP inside a VNet, blocking all public internet ingress.
*   **Azure Firewall & WAF:** Implements Layer 3-7 application filtering, IDPS (Intrusion Detection/Prevention), and Web Application Firewall rules for public entrypoints.

---

## 3. Secure Computing & Platform Posture

### Compute Protection
*   **Azure Bastion:** Managed, secure gateway providing browser-based RDP/SSH access directly over HTTPS (Port 443), eliminating VM public IP addresses.
*   **Just-in-Time (JIT) VM Access:** Restricts RDP/SSH ports dynamically via Network Security Group (NSG) rules.
*   **Azure Key Vault:** Securely manages application secrets, cryptographic keys, and certificates.
    *   *Soft Delete & Purge Protection:* Mandatory safeguards preventing accidental or malicious deletion of encryption keys.

---

## 4. Secure AI Workloads & Governance

The core differentiator of the SC-500 exam is the secure deployment of Artificial Intelligence architectures.

### Securing Azure OpenAI & Generative AI Endpoints
*   **Endpoint Hardening:** Always disable public access to Azure OpenAI endpoints; route all model queries exclusively through **Private Endpoints**.
*   **Model Access Control (RBAC):** Use Entra ID authentication instead of shared API keys to authenticate application clients querying Azure OpenAI. Assign the `Cognitive Services User` role to restrict endpoint access.
*   **Cognitive Services Customer Managed Keys (CMK):** Encrypt model configurations and fine-tuning datasets using custom keys stored in Azure Key Vault.

### AI Pipeline & Prompt Security
*   **Prompt Injection Mitigations:** Implement **Azure AI Content Safety** filter pipelines to analyze prompt inputs for jailbreaks, prompt injections, hate speech, and self-harm triggers before they reach the model.
*   **Data Leakage Prevention (RAG):**
    *   Secure **Vector Databases** (such as Azure AI Search) using RBAC and private endpoints.
    *   Apply document-level access controls to vector indices to prevent Retrieval-Augmented Generation (RAG) models from exposing restricted files to unauthorized users.
*   **CI/CD Pipeline Security for ML:** Hardening training environments (Azure Machine Learning Workspaces) and auditing training data inputs to prevent model poisoning attacks.
