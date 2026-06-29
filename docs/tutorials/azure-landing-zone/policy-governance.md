# Azure Landing Zone: Policy and Governance

Governance in an Azure Landing Zone is driven by **Azure Policy** applied at the Management Group level. This approach guarantees that all child subscriptions automatically inherit the organization's security and compliance rules.

---

## 1. The Role of Azure Policy

Azure Policy is a service used to create, assign, and manage policies. These policies enforce different rules and effects over your resources, so those resources stay compliant with your corporate standards and service level agreements.

### Policy Effects
When an Azure Policy evaluates a resource, it applies an "Effect". Common effects include:
* **Deny:** Prevents the resource from being created if it doesn't match the policy (e.g., blocking the creation of Public IP addresses on VMs).
* **Audit:** Allows the resource to be created but flags it as non-compliant in the Azure Security Center dashboard (e.g., flagging storage accounts without Secure Transfer enabled).
* **Append:** Adds specific parameters to a resource when it is created (e.g., enforcing specific IP configurations).
* **DeployIfNotExists (DINE):** Automatically deploys an ARM template to configure a resource correctly if it is missing (e.g., automatically deploying the Log Analytics agent to newly created VMs).

## 2. Core Guardrail Policies

A production-ready Landing Zone should implement the following baseline policies across all workloads:

### Security and Compliance
1. **Require MFA for all subscription owners:** Audits or Denies assignments of the Owner role if the user does not have MFA enforced.
2. **Restrict Resource Locations:** Denies the deployment of any resources outside of explicitly approved geographical regions (e.g., restricting data strictly to `eastus` and `westus` for compliance).
3. **Enforce Storage Account Secure Transfer:** Denies creation of storage accounts if HTTPS only is not enabled.
4. **Block Public Network Access:** Prevents PaaS services (like Azure SQL or Key Vault) from having public endpoints, enforcing the use of Private Link.

### Centralized Logging
* **Diagnostics Settings DINE Policy:** Uses `DeployIfNotExists` to automatically configure all resources (VNets, Key Vaults, NSGs) to stream their diagnostic logs to the centralized Log Analytics workspace in the Management Subscription.

## 3. Microsoft Defender for Cloud Integration

Azure Policy natively integrates with Microsoft Defender for Cloud (formerly Azure Security Center).
* By applying the **Azure Security Benchmark (ASB)** initiative at the Root Management Group, Defender for Cloud continuously monitors your entire estate against industry best practices.
* Non-compliant resources flagged by Azure Policy contribute to your overall **Secure Score**, providing leadership with a clear metric of the environment's security posture.
