# Microsoft AZ-900: Azure Fundamentals

This document provides quick reference notes and study sheets for the Microsoft AZ-900: Azure Fundamentals certification exam.

---

## 1. Cloud Concepts

### Why Cloud Services?
*   **High Availability (HA):** Ensures resources are reachable with minimal downtime (SLA-backed).
*   **Scalability:** Ability to handle increased load.
    *   *Vertical (Scale Up):* Adding RAM/CPU to an existing VM.
    *   *Horizontal (Scale Out):* Adding more VMs to a load balancer pools.
*   **Elasticity:** Autoscale resources dynamically based on demand spikes (de-provisioning when demand falls to save cost).
*   **Agility:** Speed of deploying resources (seconds/minutes vs. weeks for hardware procurement).
*   **Fault Tolerance (FT):** Redundancy built in to survive hardware failures without user impact.
*   **Disaster Recovery (DR):** RPO/RTO planning for restoring service after regional disasters.

### Capital Expenditure (CapEx) vs. Operational Expenditure (OpEx)
*   **CapEx:** Upfront cost for physical infrastructure (purchasing servers, buildings, networking gear). Requires depreciation planning.
*   **OpEx:** Pay-as-you-go. Spend on services as you consume them, instantly billing as business expense.

### Shared Responsibility Model
*   **On-Premises:** You own everything (hardware, hypervisor, OS, apps, data).
*   **Infrastructure as a Service (IaaS):** Cloud provider manages hardware (servers, storage, network). You manage OS, middleware, runtime, apps, data.
*   **Platform as a Service (PaaS):** Cloud provider manages hardware + OS + runtime. You only manage application code and data.
*   **Software as a Service (SaaS):** Cloud provider manages everything. You just consume the app (e.g., Office 365).

---

## 2. Core Azure Architecture

### Geographies & Regions
*   **Regions:** Geographical areas containing one or more datacenters connected via low-latency networks (e.g., East US, West Europe).
*   **Region Pairs:** Each region is paired with another at least 300 miles away to ensure business continuity during regional disaster.
*   **Availability Zones (AZs):** Physically separate datacenters *within* an Azure region. Independent power, cooling, and network. Protects against datacenter loss.

### Resource Organization Hierarchy
1.  **Management Groups:** Containers for managing access, policies, and compliance across multiple subscriptions.
2.  **Subscriptions:** Billing and access boundary wrapper for resources.
3.  **Resource Groups (RGs):** Logical containers for grouping related resources (VMs, DBs). All resources must sit in an RG, but can only belong to one.
4.  **Resources:** Instances of services (VMs, Virtual Networks, App Services).

---

## 3. Core Azure Services

### Compute Services
*   **Azure Virtual Machines:** On-demand, scalable IaaS VMs.
*   **Azure App Services:** Managed HTTP-based service for hosting web apps/APIs (PaaS).
*   **Azure Kubernetes Service (AKS):** Managed container orchestration service (Kubernetes).
*   **Azure Container Instances (ACI):** Serverless containers running on-demand without orchestrator overhead.
*   **Azure Functions:** Serverless, event-driven compute (FaaS).

### Networking Services
*   **Azure Virtual Network (VNet):** Private network in Azure allowing secure resource communication.
*   **Azure Load Balancer:** High-availability, low-latency Layer 4 (TCP/UDP) traffic distributor.
*   **Azure Application Gateway:** Layer 7 HTTP/HTTPS load balancer with Web Application Firewall (WAF) integration.
*   **VPN Gateway:** Encrypted cross-premises traffic via public internet.
*   **ExpressRoute:** Private, dedicated fiber connection bypassing public internet.

---

## 4. Azure Governance & Security

### Identity Services
*   **Microsoft Entra ID (formerly Azure Active Directory):** Cloud-based identity and access management service (not a cloud version of Windows Server AD).
*   **Multi-Factor Authentication (MFA):** Verifying identity using multiple credentials (something you know, something you have, something you are).
*   **Conditional Access:** Identity protection policies enforcing constraints (e.g., block sign-ins from outside domestic network or require MFA for administrative roles).

### Policy and Governance
*   **Azure RBAC:** Fine-grained authorization based on roles (Owner, Contributor, Reader).
*   **Azure Policy:** Enforces organizational rules and compliance (e.g., "VMs must only be deployed in West US").
*   **Azure Resource Locks:** Prevents accidental deletion or modification.
    *   `CanNotDelete` (Read/Write allowed, delete blocked).
    *   `ReadOnly` (Modifications and deletions blocked).
