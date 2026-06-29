# <img src="/docs/assets/images/azure-logo.svg" width="36" height="36" style="vertical-align: middle; margin-right: 10px;"> SC-500 Domain 1: Manage Identity, Access, and Governance

This domain focuses on configuring identity directory authentication boundaries, privileged access parameters, and auditing access anomalies using Kusto Query Language (KQL).

---

## 1. Enterprise Access Boundaries & Conditional Access

### 1.1 Entra ID Conditional Access Signal Controls
Conditional Access evaluates contextual signals during authentication to decide whether to issue OAuth tokens.
*   **Sign-in Risk Evaluation:** Integrates with Entra ID Protection to evaluate session anomalies (e.g., impossible travel, anonymous IP login) and force user MFA or password resets.
*   **Device Context:** Restricts application access unless the connecting machine is registered as compliant with Mobile Device Management (MDM) platforms like Microsoft Intune.

### 1.2 Privileged Identity Management (PIM)
PIM mitigates the risk of persistent access by enforcing **Just-in-Time (JIT)** administrative elevations.
*   **Eligible vs. Active Roles:** Users are configured as *Eligible* for administrative roles. They must explicitly request role activation to become *Active*.
*   **Elevation Constraints:** Elevation requests can require manager approvals, ticketing IDs, MFA validation, and are time-bounded (e.g. max active time of 4 hours).

### 1.3 Workload Identities
Workload Identities allow non-human credentials (such as service principals, managed identities, and AI agents) to authenticate securely.
*   **Managed Identities:** Azure-managed credentials tied directly to resources (like VMs or App Services), removing the need for developers to embed secrets in application code.

---

## 2. Auditing Identity Posture with KQL

SOC analysts write KQL queries in Log Analytics workspaces to search for compromised identities or invalid modifications.

### 2.1 Audit Brute Force Sign-Ins (Multiple Failure Code 50126)
This query flags accounts undergoing brute-force attempts by grouping failed authentication attempts:
```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == "50126" // Invalid username or password
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress, Location
| where FailedAttempts > 5
| order by FailedAttempts desc
```

### 2.2 Tracking PIM Administrative Elevations
This query audits role additions to detect unauthorized elevations:
```kusto
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Add member to role"
| extend ElevatedUser = tostring(TargetResources[0].userPrincipalName)
| extend AssignedRole = tostring(TargetResources[0].modifiedProperties[1].newValue)
| extend Actor = Identity
| project TimeGenerated, OperationName, Actor, ElevatedUser, AssignedRole
```
