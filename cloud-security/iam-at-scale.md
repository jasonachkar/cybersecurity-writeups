---
title: "AWS IAM at Scale: Federation, Delegation, and Guardrails"
type: "cloud-security"
tags:
  - cloud-security
  - iam
  - scale
date: "2026-07-25"
lastReviewed: "2026-07-25"
readingTime: 13
reviewStatus: "partially-verified"
validatedAgainst:
  - "AWS IAM security best practices — https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"
  - "Create an OIDC role for GitHub Actions — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html"
  - "Create an IAM OIDC identity provider — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html"
  - "GitHub OIDC reference — https://docs.github.com/en/actions/reference/security/oidc"
  - "GitHub OIDC in AWS — https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws"
  - "Configure a Microsoft Entra federated identity credential — https://learn.microsoft.com/entra/workload-id/workload-identity-federation-create-trust"
sourceQuality: "primary-sources-reviewed"
implementationStatus: "partially-tested"
reviewIntervalDays: 90
---

# AWS IAM at Scale: Federation, Delegation, and Guardrails

At scale, IAM is an authorization system and operating model. The design objective is short-lived, attributable sessions with narrowly delegated permissions and controls that remain understandable across accounts - not periodic rotation of thousands of long-lived access keys.

## The core decision

- Federate workforce access through an identity provider and IAM Identity Center.
- Use temporary workload credentials. For GitHub Actions, validate the AWS OIDC audience and a narrow `sub`; for EKS, prefer EKS Pod Identity where its documented constraints fit, otherwise use IRSA deliberately.
- Eliminate long-lived IAM-user access keys wherever possible. If a documented legacy exception remains, inventory, restrict, monitor, and rotate it while actively migrating it - not as a permanent 90-day ritual.
- Separate identity trust policy from permissions policy, resource policy, SCP/RCP, permission boundary, session policy, and service control behavior.
- Govern `iam:PassRole` as a privilege-escalation boundary and continuously analyze effective reachability.

## Trust model

An AWS role session requires both authentication/trust and authorization. A signed OIDC token proves claims only if AWS trusts the issuer and validates the signature, and the role trust policy still has to match the request. A signed token does not give every repository access by default, and an attacker cannot simply type a different signed `sub`. Risk appears when the trust policy accepts an overly broad pattern, accepts the wrong audience/issuer, or protects the accepted repository/ref/environment poorly.

```
flowchart LR
  W["Workforce IdP"] --> I["IAM Identity Center permission set"]
  G["GitHub OIDC issuer"] --> T["Role trust: provider, aud, sub"]
  K["EKS Pod Identity or IRSA"] --> T2["Workload role trust"]
  I --> S["Short-lived role session"]
  T --> S
  T2 --> S
  S --> E["Effective authorization"]
  P["Identity/resource policy"] --> E
  B["Boundary/session policy"] --> E
  O["SCP/RCP and service rules"] --> E
```

## Four independent decision stages

“OIDC succeeded” is not a useful security verdict. Preserve the stage that accepted or rejected a request:

1. **Signature invalid.** Reject before trusting any token claim. A verifier must resolve the intended issuer metadata/JWKS, select the correct key and permitted algorithm, and validate the JWS; a decoded JWT is not authenticated evidence.
2. **Signature valid, claims rejected.** The authentic token has an unexpected issuer/audience, is expired/not yet valid, or otherwise fails protocol validation.
3. **Claims accepted, trust policy rejected.** The provider accepted the token, but the role/federated-credential authorization does not admit its exact principal, `sub`, external ID, or requested session tags.
4. **Role assumed, permissions denied.** STS/token exchange issued a session, but identity/resource policy, a permission boundary/session policy, SCP/RCP, or service-specific authorization denies the requested API/resource.

Cloud-provider diagnostics may combine parts of this sequence, and AWS often expresses audience/subject restrictions inside the role trust policy. The engineering questions remain distinct: was the assertion authentic, was it valid for this exchange, was this identity trusted for this role, and what may the resulting session do?

## GitHub Actions OIDC trust

AWS requires a GitHub trust policy to evaluate the GitHub subject claim; AWS also documents using the audience `sts.amazonaws.com`. A narrow protected-environment example is:

<div class="language-json highlight">

<span id="__span-0-1"><span class="p">`{`</span>` `</span><span id="__span-0-2"><span class="w">` `</span><span class="nt">`"Version"`</span><span class="p">`:`</span><span class="w">` `</span><span class="s2">`"2012-10-17"`</span><span class="p">`,`</span>` `</span><span id="__span-0-3"><span class="w">` `</span><span class="nt">`"Statement"`</span><span class="p">`:`</span><span class="w">` `</span><span class="p">`[`</span>` `</span><span id="__span-0-4"><span class="w">` `</span><span class="p">`{`</span>` `</span><span id="__span-0-5"><span class="w">` `</span><span class="nt">`"Effect"`</span><span class="p">`:`</span><span class="w">` `</span><span class="s2">`"Allow"`</span><span class="p">`,`</span>` `</span><span id="__span-0-6"><span class="w">` `</span><span class="nt">`"Principal"`</span><span class="p">`:`</span><span class="w">` `</span><span class="p">`{`</span>` `</span><span id="__span-0-7"><span class="w">` `</span><span class="nt">`"Federated"`</span><span class="p">`:`</span><span class="w">` `</span><span class="s2">`"arn:aws:iam::<account-id>:oidc-provider/token.actions.githubusercontent.com"`</span>` `</span><span id="__span-0-8"><span class="w">` `</span><span class="p">`},`</span>` `</span><span id="__span-0-9"><span class="w">` `</span><span class="nt">`"Action"`</span><span class="p">`:`</span><span class="w">` `</span><span class="s2">`"sts:AssumeRoleWithWebIdentity"`</span><span class="p">`,`</span>` `</span><span id="__span-0-10"><span class="w">` `</span><span class="nt">`"Condition"`</span><span class="p">`:`</span><span class="w">` `</span><span class="p">`{`</span>` `</span><span id="__span-0-11"><span class="w">` `</span><span class="nt">`"StringEquals"`</span><span class="p">`:`</span><span class="w">` `</span><span class="p">`{`</span>` `</span><span id="__span-0-12"><span class="w">` `</span><span class="nt">`"token.actions.githubusercontent.com:aud"`</span><span class="p">`:`</span><span class="w">` `</span><span class="s2">`"sts.amazonaws.com"`</span><span class="p">`,`</span>` `</span><span id="__span-0-13"><span class="w">` `</span><span class="nt">`"token.actions.githubusercontent.com:sub"`</span><span class="p">`:`</span><span class="w">` `</span><span class="s2">`"repo:jasonachkar/cybersecurity-writeups:environment:production"`</span>` `</span><span id="__span-0-14"><span class="w">` `</span><span class="p">`}`</span>` `</span><span id="__span-0-15"><span class="w">` `</span><span class="p">`}`</span>` `</span><span id="__span-0-16"><span class="w">` `</span><span class="p">`}`</span>` `</span><span id="__span-0-17"><span class="w">` `</span><span class="p">`]`</span>` `</span><span id="__span-0-18"><span class="p">`}`</span>` `</span>

</div>

This is illustrative. Verify the exact subject generated by the selected GitHub event/environment and protect that environment with reviewers and branch/tag rules. Use separate roles for build, staging, and production. A broad pattern such as `repo:organization/*` intentionally delegates trust to many matching repositories and requires organization-wide repository/workflow governance; it is not equivalent to an exact repository and environment binding.

A branch subject and an environment subject are alternatives. When a job references a GitHub environment, the default `sub` uses the environment and does not also carry the branch form. GitHub now also documents immutable owner/repository-ID subject formats for repositories created after July 15, 2026, repositories that opt in, and qualifying renames/transfers. Inspect the actual token for the repository and bind AWS to that exact format; do not mechanically copy this readable example.

An exact branch condition for a repository using the readable subject format is:

<div class="language-json highlight">

<span id="__span-1-1"><span class="p">`{`</span>` `</span><span id="__span-1-2"><span class="w">` `</span><span class="nt">`"StringEquals"`</span><span class="p">`:`</span><span class="w">` `</span><span class="p">`{`</span>` `</span><span id="__span-1-3"><span class="w">` `</span><span class="nt">`"token.actions.githubusercontent.com:aud"`</span><span class="p">`:`</span><span class="w">` `</span><span class="s2">`"sts.amazonaws.com"`</span><span class="p">`,`</span>` `</span><span id="__span-1-4"><span class="w">` `</span><span class="nt">`"token.actions.githubusercontent.com:sub"`</span><span class="p">`:`</span><span class="w">` `</span><span class="s2">`"repo:example-security/cloud-controls:ref:refs/heads/main"`</span>` `</span><span id="__span-1-5"><span class="w">` `</span><span class="p">`}`</span>` `</span><span id="__span-1-6"><span class="p">`}`</span>` `</span>

</div>

On each exchange, validate through configuration:

- canonical GitHub OIDC provider URL and current provider handling per AWS documentation;
- audience expected by the AWS action/partition;
- exact repository owner/name or immutable IDs and the branch, tag, pull request, or environment subject that GitHub actually issues;
- repository visibility/ownership controls if relevant to the claim set;
- session duration, session name/tags where supported, and narrow role permissions.

The workflow still needs `id-token: write`; this permits requesting an OIDC token but does not itself grant AWS access. The AWS trust and permissions remain decisive.

The [IAM/OIDC decision lab](../labs/iam-oidc/README.md) tests exact branch and environment trust separately, including invalid-signature, wrong-issuer/audience/ repository/ref/environment, trust-rejection, and post-assumption permission-denial fixtures.

## Workload identity on EKS

AWS currently recommends EKS Pod Identity where possible. It centralizes the service principal trust model and supports session tags, but has documented platform/version, node-agent, same-account, and service limitations. IRSA uses a cluster OIDC provider and service-account subject conditions and remains appropriate where Pod Identity is unsupported or its model does not fit.

For either model:

- dedicate Kubernetes service accounts to workloads and disable default token mount where unnecessary;
- bind one narrow AWS role per meaningful workload trust boundary;
- restrict Kubernetes RBAC that can create/modify pods and service accounts because it may confer workload identity;
- enforce IMDS/node-role protections so a pod cannot fall back to broader node credentials;
- correlate Kubernetes audit, STS, and CloudTrail identity/session data.

Do not call containers a complete boundary: pods on a node share a kernel, and node/ cluster compromise can affect workload identity controls.

The offline lab includes an IRSA trust fixture pinned to one cluster issuer, `sts.amazonaws.com` audience, namespace, and service account. It does not create an EKS cluster or exercise EKS Pod Identity.

## Third-party role trust and session attribution

For a vendor that assumes customer roles, trust the vendor's narrow AWS principal and require a unique customer external ID generated and managed by the vendor to address the cross-account confused-deputy problem. AWS explicitly does not treat an external ID as a secret, so it is a trust discriminator, not an authentication credential.

If the vendor passes session tags for ABAC/audit attribution, the role trust policy must also authorize `sts:TagSession`. Restrict both allowed keys (`aws:TagKeys`) and values (`aws:RequestTag/<key>`), and decide deliberately which tags may be transitive. Do not let a caller self-assert privileged tags such as `admin=true`. The offline lab tests the exact vendor principal, external ID, required tags, an extra tag, and the missing-`sts:TagSession` failure.

## `iam:PassRole` and delegated service roles

`iam:PassRole` lets a principal tell an AWS service to use a role. The role trust policy must trust that service, and the role must be in the same account as the principal passing it. Authorization should constrain:

- explicit role ARNs or tightly governed role paths;
- destination service using `iam:PassedToService` where supported;
- associated resource using `iam:AssociatedResourceArn` where semantics are documented and tested;
- the service API actions that create/update the resource using the role.

The effective privilege is the intersection of who can pass which role, to which service/resource, through which create/update APIs. Review all dimensions. The `PassRole` permission is evaluated during the service API and does not produce a standalone CloudTrail `PassRole` event; investigate the destination service event and role ARN.

The lab permits one exact ECS task role only for `ecs-tasks.amazonaws.com` and one task-definition family. It rejects another role, service, and associated resource, and separately asserts that the passed role trusts the destination service.

## Permission architecture

Use accounts as blast-radius and policy boundaries, organized under AWS Organizations. SCPs restrict the maximum permissions available in member accounts; they do not grant permissions. Permission boundaries restrict delegated role/user identity policies; they do not grant permissions. Resource policies, KMS key policies, role trust policies, session policies, service-specific authorization, and Organizations resource control policies where applicable all contribute to effective access.

Delegated IAM administration must protect the boundary itself. Require the approved `iam:PermissionsBoundary` when creating entities, scope creation/policy-management to a governed role path, and deny removal or replacement of the boundary unless a separate control-plane role owns that change. A boundary constrains effective permissions; it does not prevent its own removal by a principal allowed to call the relevant IAM APIs. The lab positively tests role creation with the approved boundary and negatively tests missing/alternate boundaries, path escape, removal, and replacement.

Build reusable job-function roles/permission sets, then narrow resource scope and conditions. Avoid attaching administrator policies to CI, platform, and incident roles for convenience. Use separate break-glass access with strong authentication, just-in-time approval, dedicated monitoring, tested recovery, and post-use review.

## Long-lived access keys

AWS IAM best practices prioritize federation and temporary credentials. The target state is no IAM-user key for humans, CI/CD, EC2, containers, or supported AWS services. Use roles, instance/task profiles, EKS identities, service roles, and OIDC/ SAML federation.

For a legacy exception:

1. name an owner, workload, business reason, data/actions, network path, and migration deadline;
2. restrict policy/resource conditions and place the secret in a managed secret store, never source or general CI variables;
3. monitor use, source, and anomalous behavior;
4. rotate with overlap and rollback only as required by the integration;
5. disable, observe, then delete when migration completes.

Age alone is a weak signal: an unused new key is still unnecessary, and rotating a persistently overprivileged key does not reduce its inherent exposure.

## Analysis and continuous validation

Use IAM Access Analyzer for external/internal access findings and policy generation/ validation, service last-accessed information with context, CloudTrail, AWS Config, organization policy checks, and graph analysis. Community tools such as PMapper can assist reachability review, but pin/test tool versions and treat their results as analysis rather than authoritative proof.

AWS's IAM Policy Simulator can test identity policies and one permission boundary, but AWS documents important gaps: it does not simulate cross-account access for roles/ users, resource-based policies for IAM roles, RCPs, or SCPs containing conditions. It also does not retrieve GitHub/EKS JWKS, validate an OIDC signature, exchange the token through STS, or establish end-to-end role trust. Use simulation as a pre-deployment check, then run allowed and denied exchanges/API calls in a disposable account and capture CloudTrail evidence. Do not describe simulator output as a successful `AssumeRoleWithWebIdentity` test.

Test the cases that should fail: cross-account assume role, wrong GitHub repository/ref/ environment/audience, unapproved service-account identity, PassRole to an unauthorized role/service, access outside resource tags/paths, and action from an SCP-denied account.

## Reproducible evidence

Run the dependency-free offline checks from the repository root:

<div class="language-powershell highlight">

<span id="__span-2-1"><span class="n">`node`</span>` `<span class="n">`labs`</span><span class="p">`/`</span><span class="n">`iam-oidc`</span><span class="p">`/`</span><span class="n">`tests`</span><span class="p">`/`</span><span class="n">`run-tests`</span><span class="p">`.`</span><span class="n">`js`</span>` `</span>

</div>

Expected output is `PASS: 45 IAM/OIDC structural and policy-model evaluations completed.` The tests exercise the four decision stages plus Azure federation, IRSA, third-party external ID/session tags, boundary mutation, and restricted PassRole. They do not call cloud APIs or implement JWT cryptography; the lab README defines the evidence boundary and required disposable-cloud validation.

## Failure modes and rollback

- OIDC or IdP outage: use a controlled break-glass path, not cached permanent CI keys.
- Overbroad trust: restrict immediately, revoke active sessions where feasible, investigate CloudTrail, rotate any accessed downstream secrets, and review builds/ deployments from affected sessions.
- Permission reduction breaks workloads: roll back a versioned policy through review; do not attach AdministratorAccess as an automated fallback.
- Lost organization controls: detect drift and require delegated policy changes through a protected pipeline with management-account safeguards.

## Operational checklist

Humans and workloads use temporary, attributable sessions.

GitHub trust validates audience and exact intended subject/environment.

EKS workload identity choice and node/metadata protections are documented.

Third-party trust requires the exact principal and unique external ID; session tag keys/values are constrained when tags are used.

`iam:PassRole`, destination APIs, role trust, and passed role permissions are reviewed together.

SCPs/boundaries are described as guardrails, not grants.

Delegated principals cannot omit, replace, or remove required boundaries.

Long-lived keys have a migration deadline, not only a rotation date.

Break-glass and identity-provider outage procedures are rehearsed.

Trust/policy/role/access-key changes and unexpected sessions alert centrally.

## Limitations

Policy snippets require account/partition/service-specific review. AWS adds services, condition keys, workload-identity capabilities, and Organizations controls over time; revalidate before production changes. The offline lab implements a documented subset of policy behavior, not AWS IAM or Azure RBAC, and does not establish cloud execution.

## References

- [AWS IAM security best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [Create an OIDC role for GitHub Actions](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html)
- [Create an IAM OIDC identity provider](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html)
- [GitHub OIDC reference](https://docs.github.com/en/actions/reference/security/oidc)
- [GitHub OIDC in AWS](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws)
- [Configure a Microsoft Entra federated identity credential](https://learn.microsoft.com/entra/workload-id/workload-identity-federation-create-trust)
- [Third-party role access and external IDs](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_third-party.html)
- [Pass session tags in AWS STS](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html)
- [Permissions boundaries for IAM entities](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)
- [Grant a principal permission to pass a role](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html)
- [IAM policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
- [IAM Policy Simulator capabilities and limitations](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html)
- [IAM roles for EKS service accounts](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)
- [EKS IAM roles for service accounts and Pod Identity comparison](https://docs.aws.amazon.com/eks/latest/userguide/service-accounts.html)
- [PMapper source repository](https://github.com/nccgroup/PMapper)
