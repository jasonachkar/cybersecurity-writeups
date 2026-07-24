---
title: "Azure Landing Zone: Policy and Governance"
type: "tutorial"
tags:
  - azure
  - azure-policy
  - management-groups
  - governance
date: "2026-07-23"
lastReviewed: "2026-07-23"
readingTime: 10
reviewStatus: "partially-verified"
validatedAgainst:
  - "Azure Policy scope, effect, remediation, and exemption documentation checked 2026-07-23"
  - "Microsoft Entra Conditional Access and Privileged Identity Management documentation checked 2026-07-23"
  - "Microsoft Defender for Cloud recommendation and secure-score documentation checked 2026-07-23"
sourceQuality: "primary-sources-reviewed"
implementationStatus: "illustrative"
reviewIntervalDays: 180
---

# Azure Landing Zone: Policy and Governance

Azure Policy evaluates Azure Resource Manager resources and actions against policy
definitions. Assigning an initiative at a management group makes it applicable to
descendant subscriptions and resources, but that inheritance is not an unconditional
guarantee: assignment exclusions (`notScopes`), policy exemptions, definition mode,
resource-provider aliases, effect behavior, and evaluation timing all affect the
result.

The examples here are design guidance, not a deploy-ready baseline. Test every
definition against the exact API versions and resource types in a canary subscription.

## Scope and ownership

Use management groups to separate platform, landing-zone, sandbox, and decommissioned
subscriptions. Put a policy assignment at the highest scope that shares the same
requirement, then delegate exemptions and remediation narrowly.

For each assignment record:

- the control owner and business requirement;
- included scope, exclusions, and time-bounded exemptions;
- effect and assignment `enforcementMode`;
- managed identity and least-privilege remediation role, if required;
- expected behavior for new, updated, and existing resources;
- a negative test and a rollback procedure.

An exemption is part of the effective policy state, not an invisible exception.
Monitor exemption creation, expiry, and scope.

## Choose effects deliberately

| Effect | Request-time and existing-resource behavior | Important limitation |
| --- | --- | --- |
| `deny` | Rejects a matching create/update request. Existing resources can be reported noncompliant. | It does not repair existing resources, and only properties exposed through applicable aliases can be evaluated as designed. |
| `audit` / `auditIfNotExists` | Records noncompliance without blocking the request. | Compliance data appears in Azure Policy; it is not automatically a Defender for Cloud alert or secure-score change. |
| `modify` | Adds, replaces, or removes supported properties during create/update. A remediation task can update existing resources. | Remediation needs an assignment identity and appropriate RBAC; only modifiable aliases and supported operations work. |
| `append` | Adds fields during create/update; a conflicting requested value can cause denial. | It does not change existing resources. Prefer `modify` for tags and other supported properties; retain `append` only when its narrower semantics are intended. |
| `deployIfNotExists` | After resource-provider success, evaluates for a related configuration and can run a deployment. A remediation task can handle existing resources. | It is not an atomic mutation of the original request and requires an identity, correct role assignments, and type-specific templates. |

Remediation is not implied by a noncompliant state. Create and monitor remediation
tasks for `modify` and `deployIfNotExists` assignments when existing resources must be
changed.

## Baseline control families

Start with tested built-in initiatives where they express the requirement, then add
custom definitions only for gaps.

1. **Location and resource-type boundaries** — deny unsupported locations or resource
   types while accounting for global resource types, metadata locations, and approved
   exemptions.
2. **Network exposure** — audit or deny public network access per resource provider
   only after private DNS, Private Link, deployment agents, and recovery paths have
   been tested.
3. **Data protection** — enforce secure transport, supported TLS versions, retention,
   and encryption settings using resource-specific aliases.
4. **Diagnostics** — use type-specific `deployIfNotExists` definitions to create
   diagnostic settings for supported resources. Log categories differ by resource
   type; a single generic template does not cover every service.
5. **Taxonomy** — use `modify` for supported tag operations and remediation of existing
   resources. Do not rely on `append` as a general repair mechanism.

## Identity and privileged access are separate controls

Do not describe a generic Azure Policy rule as “require MFA for every Owner.” Azure
Policy primarily evaluates Resource Manager request and resource properties; an RBAC
assignment does not expose whether its assignee registered or satisfied MFA.

Use:

- Microsoft Entra Conditional Access to require an appropriate authentication strength
  for Azure management;
- Microsoft Entra Privileged Identity Management for eligible, time-bound privileged
  role activation, approval, and activation controls;
- Azure RBAC and access reviews to limit and periodically reassess Owner assignments.

Azure Policy does not configure MFA for identities or determine whether an Owner role
assignment is safe. Govern authentication and privileged role activation through
Conditional Access and PIM instead.

## Defender for Cloud is not the policy engine

Microsoft Defender for Cloud assesses cloud posture, produces security
recommendations, calculates secure-score models, and—when paid workload protection
plans are enabled—adds service-specific threat protection. Azure Policy supplies or
supports some configuration and assessment plumbing, but the products are not
interchangeable.

When Defender for Cloud is enabled, the Microsoft cloud security benchmark is applied
by default to the subscription. Do not claim that every Azure Policy noncompliance
changes secure score: score inclusion depends on the recommendation, maturity, model,
and enabled environment. Treat secure score as a prioritization signal, not proof that
a control is effective.

## Validation checklist

- Test deny behavior with allowed and rejected deployment fixtures.
- Confirm exclusions, exemptions, and assignment `enforcementMode`.
- Verify the assignment identity has only the remediation permissions it needs.
- Run remediation against a canary scope and inspect failed deployments.
- Confirm diagnostics arrive in the intended destination and that operators can query
  them.
- Test Conditional Access and PIM with emergency-access accounts protected according
  to Microsoft's guidance.
- Review Defender for Cloud recommendations independently from Azure Policy compliance.

## Validation status

The semantics in this page were checked against the Microsoft primary sources below on
2026-07-23. No policy definitions, ARM deployments, Conditional Access policies, or
Defender plans were executed; implementation status remains **illustrative**.

## References

- [Azure Policy overview and assignment scope](https://learn.microsoft.com/azure/governance/policy/overview)
- [Azure Policy effect basics](https://learn.microsoft.com/azure/governance/policy/concepts/effect-basics)
- [Azure Policy `modify` effect and remediation](https://learn.microsoft.com/azure/governance/policy/concepts/effect-modify)
- [Azure Policy `append` effect](https://learn.microsoft.com/azure/governance/policy/concepts/effect-append)
- [Azure Policy exemptions](https://learn.microsoft.com/azure/governance/policy/concepts/exemption-structure)
- [Microsoft Entra Conditional Access](https://learn.microsoft.com/entra/identity/conditional-access/)
- [Microsoft Entra Privileged Identity Management](https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-configure)
- [Microsoft Defender for Cloud recommendations](https://learn.microsoft.com/azure/defender-for-cloud/review-security-recommendations)
- [Secure score in Microsoft Defender for Cloud](https://learn.microsoft.com/azure/defender-for-cloud/secure-score-security-controls)
