---
title: "AWS Multi-Account Landing Zones: Guardrails and Control-Plane Isolation"
id: "multi-account-landing-zones"
navTitle: "Landing zones"
order: 30
type: "cloud-security"
tags:
  - cloud-security
  - multi
  - account
  - landing
  - zones
date: "2026-07-25"
lastReviewed: "2026-07-25"
reviewStatus: "partially-verified"
validatedAgainst:
  - "AWS Organizations: Service control policies — https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html"
  - "AWS Organizations: SCP evaluation — https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_evaluation.html"
  - "AWS Organizations: SCP examples and Region restriction — https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples.html"
  - "AWS IAM: `aws:RequestedRegion` global condition key — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-requestedregion"
  - "AWS IAM: Cross-account policy evaluation — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic-cross-account.html"
  - "AWS IAM Access Analyzer: External access findings — https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-findings.html"
sourceQuality: "primary-sources-reviewed"
implementationStatus: "illustrative"
reviewIntervalDays: 90
---

# AWS Multi-Account Landing Zones: Guardrails and Control-Plane Isolation

A landing zone is an operating model for accounts, identity, logging, network connectivity, and preventive controls. An AWS account is a useful blast-radius and administrative boundary, but the boundary holds only when the organization control plane, cross-account trust, and resource policies are governed together.

This article describes a reference design. It is **not a deploy-ready configuration**: the SCP is illustrative, has not been evaluated in a live organization, and must be tested against each workload's APIs, global services, automation roles, and recovery procedures.

## Assumptions and security objectives

The design assumes:

- AWS Organizations has all features enabled and member accounts are provisioned through a controlled account-vending process.
- Workforce access is federated, workload access uses temporary credentials, and management-account credentials are reserved for organization administration.
- Organization-wide CloudTrail, AWS Config, GuardDuty, Security Hub CSPM, and IAM Access Analyzer are configured where supported, with logs stored in a separate log-archive account.
- Break-glass access is tested, monitored, and unable to silently weaken logging or account governance.

The objectives are to limit lateral movement between workloads, keep security evidence outside workload-administrator control, and make organization-level changes both rare and observable.

## Threat and trust boundaries

| Boundary | Representative failure | Required control |
|----|----|----|
| Workload to account | A compromised workload reaches unrelated data or administration APIs. | Narrow workload roles, permissions boundaries where appropriate, resource policies, network segmentation, and service-specific controls. |
| Account to account | A broad role trust lets a lower-trust account assume a production role. | Explicit principals, narrow OIDC/SAML claims, session controls, and `sts:ExternalId` for third-party confused-deputy scenarios. |
| Member account to organization | An administrator leaves the organization or disables delegated security integration. | SCP guardrails, Control Tower controls, restricted organization administration, and alerting. |
| Resource policy to external principal | A bucket, queue, key, or role trust authorizes a principal outside the intended organization. | `aws:PrincipalOrgID` where supported, IAM Access Analyzer, resource control policies where applicable, and service-specific public-access controls. |
| Management account | Its principal can change organization policy and is not constrained by SCPs. | No workloads, tightly controlled federation, hardware-backed emergency access, approval, and independent monitoring. |

SCPs do not protect the identity provider, CI/CD system, SaaS administrator, DNS registrar, or an external principal's account. Those are separate trust boundaries.

## SCP semantics that matter

An SCP defines the maximum permissions available to principals in affected **member accounts**. It does not grant permission. A request still needs an applicable allow from an identity- or resource-based policy, and an explicit deny in any applicable policy wins.

For an allow-list SCP model, an action needs an allow at every level in the path from the organization root through each OU to the account. For a deny-list model, the AWS-managed `FullAWSAccess` SCP commonly remains attached while targeted explicit denies are added. Removing `FullAWSAccess` without supplying the required allows can cause broad implicit denial.

An SCP attached to a parent cannot be overridden by a child SCP. Moving an account, changing an attachment, disabling the SCP policy type, or changing a condition can, however, change the effective boundary. Treat these as privileged control-plane operations and alert on them.

### Enforcement and bypass conditions

| Condition | What the SCP does | What it does not do |
|----|----|----|
| Member-account IAM user, role, role session, or member root user | Limits the principal's maximum permissions. | Grant the principal an action. |
| Delegated administrator account | Still applies because it remains a member account. | Prevent the management account from replacing the delegation. |
| Management-account user or role | Nothing; SCPs do not apply. | Protect organization administration. |
| Service-linked role | Nothing; SCPs do not restrict service-linked-role permissions. | Prevent a service from performing its documented linked-role operations. |
| Direct external principal authorized by a member resource policy | The external principal is not constrained by the resource account's SCP; controls attached to the principal's own account may apply. | Repair an overbroad bucket, key, queue, or role resource policy. |
| Explicit deny at any applicable organization level | Denies the matching request. | Cover APIs, resources, principals, Regions, or condition values that the statement does not match. |

Cross-account requests require both the trusted-principal side and trusting-resource side to allow the request. Because SCPs apply to principals of the accounts to which they are attached, use resource policies and, where supported, resource control policies to establish the resource-side organization perimeter. If an external caller assumes a role in a member account, subsequent requests using that role session are made by a member-account principal and are constrained by that account's applicable SCPs.

## Reference account structure

```text
Organization root
├── Security OU
│ ├── Log archive
│ └── Security tooling / delegated administration
├── Infrastructure OU
│ ├── Network
│ └── Shared services
├── Workloads OU
│ ├── Production
│ └── Non-production
├── Sandbox OU
└── Suspended / quarantine OU
```

Keep workloads out of the management account. Delegate supported security services to the security-tooling account, but remember that delegated administration does not transfer all Organizations privileges and does not make that account immune to SCPs. Use a distinct log-archive account with tightly limited write and delete paths.

## Illustrative member-account SCP

The following deny-list fragment demonstrates two guardrails. It is intentionally incomplete and must not be copied into production without service-impact analysis.

```json
{
 "Version": "2012-10-17",
 "Statement": [
 {
 "Sid": "DenyLeavingOrganization",
 "Effect": "Deny",
 "Action": "organizations:LeaveOrganization",
 "Resource": "*"
 },
 {
 "Sid": "DenyUnsupportedRegionsWithGlobalServiceExceptions",
 "Effect": "Deny",
 "NotAction": [
 "account:*",
 "aws-portal:*",
 "budgets:*",
 "cloudfront:*",
 "globalaccelerator:*",
 "iam:*",
 "networkmanager:*",
 "organizations:*",
 "route53:*",
 "route53domains:*",
 "support:*",
 "waf:*"
 ],
 "Resource": "*",
 "Condition": {
 "StringNotEquals": {
 "aws:RequestedRegion": [
 "ca-central-1",
 "us-east-1"
 ]
 }
 }
 }
 ]
}
```

This example has important limitations:

- Apply it only to intended member-account OUs/accounts. It cannot constrain the management account.
- AWS global services use control planes that are hosted in particular Regions, often `us-east-1`. The `NotAction` list is workload- and service-dependent; compare it with AWS's current example before every rollout.
- `aws:RequestedRegion` identifies the endpoint handling the request. It does not necessarily constrain every Region affected by an operation. For example, some cross-Region service operations need service-specific condition keys or resource controls.
- Exempting an entire global service from the Region statement means this statement does not restrict that service. Add separate, service-specific guardrails where required.
- A deny can break account vending, incident response, Control Tower remediation, and service integrations. Roll out to a canary OU and inspect authorization failures before broader attachment.

Do not add an exemption simply because an automation fails. Determine the exact principal, action, resource, and request context, then make the narrowest justified change.

## Operational rollout

1. Inventory current service use and organization policy attachments.
2. Model the intended OU path and identify who can move accounts or alter policies.
3. Test policies in a non-production canary OU with representative provisioning, backup, security, billing, support, and recovery workflows.
4. Use IAM service-last-accessed data and CloudTrail authorization failures to refine scope; neither proves that an unused permission is safe to remove by itself.
5. Promote by OU in small batches with a documented rollback and an out-of-band recovery path.
6. Continuously alert on policy changes, account moves, organization departure attempts, external resource access, and security-service configuration changes.

## Validation status and limitations

| Artifact or claim | Status |
|----|----|
| SCP and Organizations semantics | Reviewed against the AWS primary sources below on 2026-07-23. |
| JSON example | Checked by the repository fenced-code validator; no live AWS evaluation. |
| Service compatibility | Not tested; the global-service exception list is illustrative and will change with adopted services. |
| Control effectiveness | I haven't measured this in a live organization. You'd want to validate it with canary accounts and confirm the denied cases actually get denied. |

## References

- [AWS Organizations: Service control policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)
- [AWS Organizations: SCP evaluation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_evaluation.html)
- [AWS Organizations: SCP examples and Region restriction](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples.html)
- [AWS IAM: `aws:RequestedRegion` global condition key](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-requestedregion)
- [AWS IAM: Cross-account policy evaluation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic-cross-account.html)
- [AWS IAM Access Analyzer: External access findings](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-findings.html)
- [AWS Control Tower: Guidance for organization and account structure](https://docs.aws.amazon.com/controltower/latest/userguide/organizations.html)
