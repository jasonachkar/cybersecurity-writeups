# <img src="/docs/assets/images/azure-logo.svg" width="36" height="36" style="vertical-align: middle; margin-right: 10px;"> AZ-900 Domain 3: Describe Azure Management & Governance

This section covers Entra ID authentication, governance policy rules, cost tools, and monitoring architectures.

---

## 1. Identity & Directory Services

### 1.1 Microsoft Entra ID (formerly Azure Active Directory)
A cloud-native identity directory service managing users, groups, and applications.
*   **Authentication (AuthN):** Verification of identity credentials (MFA, passwordless, SSO).
*   **Authorization (AuthZ):** Setting permissions to determine what resources the validated entity can access.

### 1.2 Conditional Access
Entra ID's access decision engine. It evaluates signals (user risk, location, device compliance) before issuing OAuth tokens.
*   *Signal -> Decision Engine (Policies) -> Action (Allow, Require MFA, Block)*

---

## 2. Resource Governance & Administration

### 2.1 Role-Based Access Control (RBAC)
Authorizes *who* has access to resources and *what* they can execute.
*   **Scopes:** Inherited from Management Groups -> Subscriptions -> Resource Groups -> Resources.
*   **Core Roles:**
    *   *Owner:* Full access including permission delegation.
    *   *Contributor:* Can modify resources but cannot delegate access.
    *   *Reader:* View-only access.

### 2.2 Azure Policy
Enforces resource constraints and compliance audits across subscriptions. Unlike RBAC (which controls *who*), Azure Policy controls *what properties* a resource can have.
*   *Example:* Denying deployment of virtual machines unless they are configured with encryption keys.

### 2.3 Resource Locks
Overrides RBAC policies to prevent accidental data deletion or resource modification.
*   `CanNotDelete`: Resources can be read and modified but not deleted.
*   `ReadOnly`: Resources can only be viewed. Modifications and deletions are blocked.

---

## 3. Cost Management & Monitoring

### 3.1 Cost Management Tools
*   **TCO Calculator (Total Cost of Ownership):** Used *before* migration to compare the cost of running workloads on-premises vs. in Azure.
*   **Pricing Calculator:** Estimates monthly resource consumption costs prior to deployment.
*   **Azure Cost Management:** Monitors and analyzes actual billing spend, enabling alerts when costs reach predefined limits.

### 3.2 Monitoring & Posture Architecture
*   **Azure Monitor:** Aggregates performance logs and metrics from resources.
*   **Azure Service Health:** Alerts you to Microsoft datacenter outages and scheduled maintenance windows.
*   **Azure Advisor:** Evaluates cloud configurations and suggests optimizations for cost, security, reliability, operational excellence, and performance.
