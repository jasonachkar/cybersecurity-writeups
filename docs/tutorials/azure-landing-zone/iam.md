# Azure Landing Zone: Identity and Access Management (IAM)

A secure Azure Landing Zone delegates permissions systematically using Role-Based Access Control (RBAC) and Privileged Identity Management (PIM), ensuring that users only have the access they need, exactly when they need it.

---

## 1. Role-Based Access Control (RBAC) at Scale

Do not assign permissions directly to users or at the individual resource level. This quickly becomes unmanageable.

* **Group-Based Assignment:** Always assign Azure Roles to Azure AD (Entra ID) Security Groups. Add users to the groups.
* **Management Group Scope:** Assign broad, read-only or auditing roles at the Management Group level so they cascade down to all subscriptions.
* **Subscription Scope:** Assign workload-specific roles (e.g., `Virtual Machine Contributor`) at the specific Subscription or Resource Group level.

### Standard Operating Roles
Establish baseline groups for operations:
- `AZ-Global-Readers`: Assigned `Reader` at the Root Management Group.
- `AZ-Network-Admins`: Assigned `Network Contributor` at the Connectivity Subscription.
- `AZ-Security-Admins`: Assigned `Security Admin` at the Root Management Group.

## 2. Privileged Identity Management (PIM)

No user should have standing, persistent access to administrative roles like `Owner` or `Contributor`.

* **Just-in-Time (JIT) Access:** Users are made "Eligible" for a role. When they need to perform a task, they activate the role for a limited time (e.g., 2 hours).
* **Approval Workflows:** Highly privileged roles (like Subscription Owner) should require manual approval from another administrator before the role is activated.
* **MFA Enforcement:** PIM requires users to perform Multi-Factor Authentication before activating any privileged role.

## 3. Workload Identities

Applications and scripts running in Azure should not use hardcoded passwords or shared API keys.

* **Managed Identities:** Azure resources (like VMs, App Services, or Functions) can be assigned a Managed Identity. Azure automatically manages the lifecycle and credentials of this identity. The application can request an Azure AD token to authenticate to other services (like Key Vault or SQL) without any code changes.
* **Federated Identity Credentials (OIDC):** For workloads running outside of Azure (e.g., GitHub Actions CI/CD pipelines or on-premises Kubernetes), use OpenID Connect (OIDC) federation. This allows the external workload to assume an Azure AD App Registration identity temporarily, completely eliminating the need to store long-lived Client Secrets in GitHub.
