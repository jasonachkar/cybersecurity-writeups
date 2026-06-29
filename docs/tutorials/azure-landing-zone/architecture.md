# Azure Landing Zone: Architecture Overview

An Azure Landing Zone is the output of a multi-subscription Azure environment that accounts for scale, security governance, networking, and identity. It serves as the foundation for deploying production workloads in the cloud.

---

## 1. Core Principles of a Landing Zone

*   **Subscription Democratization:** Subscriptions should be used as a unit of management and scale, not just a billing boundary.
*   **Policy-Driven Governance:** Utilize Azure Policy to enforce guardrails rather than relying solely on RBAC.
*   **Single Control and Management Plane:** Centralize logging, monitoring, and networking for full visibility.
*   **Application-Centric and Archetype-Neutral:** The landing zone should support any application archetype (IaaS, PaaS, or Kubernetes).

## 2. Management Group Hierarchy

The core of an Azure Landing Zone is a robust Management Group structure. This allows you to apply Azure Policies and RBAC at scale across multiple subscriptions.

```mermaid
flowchart TD
    ROOT["Tenant Root Group"] --> MGMT["Platform (Management Group)"]
    ROOT --> LANDING["Landing Zones (Management Group)"]
    ROOT --> SANDBOX["Sandboxes (Management Group)"]
    ROOT --> DECOMM["Decommissioned (Management Group)"]

    MGMT --> ID["Identity Sub"]
    MGMT --> NET["Connectivity Sub"]
    MGMT --> SEC["Management Sub (Log Analytics)"]

    LANDING --> CORP["Corp (Internal Apps)"]
    LANDING --> ONLINE["Online (Public Facing)"]
    
    CORP --> APP1["App 1 Sub"]
    ONLINE --> APP2["App 2 Sub"]

    style ROOT fill:#2563eb,color:#fff,stroke:#1d4ed8
    style MGMT fill:#0891b2,color:#fff,stroke:#0e7490
    style LANDING fill:#059669,color:#fff,stroke:#047857
    style SANDBOX fill:#d97706,color:#fff,stroke:#b45309
    style DECOMM fill:#475569,color:#fff,stroke:#334155
```

### Platform Subscriptions
These are highly controlled subscriptions that provide shared services to the rest of the environment:
1.  **Identity Subscription:** Hosts Active Directory Domain Controllers, Azure AD Connect, or specialized identity appliances.
2.  **Connectivity Subscription:** Hosts the Azure Virtual WAN hub, ExpressRoute circuits, VPN gateways, and Azure Firewall.
3.  **Management Subscription:** Hosts the centralized Log Analytics Workspace, Azure Monitor, and Microsoft Defender for Cloud configurations.

### Landing Zone Subscriptions
These host your actual workloads. They are typically divided into:
1.  **Corp:** Workloads that do not have direct inbound internet access. They connect via the Hub (Connectivity Subscription).
2.  **Online:** Workloads that require direct inbound internet access (often behind an Azure Application Gateway or Front Door).
