# IAM and workload-identity decision lab

This dependency-free offline lab tests exact workload-identity trust fixtures and a small, explicit subset of authorization semantics. It exists to prevent four different decisions from being collapsed into “the token worked”:

1. `SIGNATURE_INVALID` - an external cryptographic-verifier boundary did not authenticate the token signature.
2. `CLAIMS_REJECTED` - the signature boundary succeeded, but issuer, audience, or lifetime checks failed.
3. `TRUST_POLICY_REJECTED` - the token/caller was authenticated and its protocol claims were accepted, but the role trust policy or federated credential rejected the principal, subject, external ID, or requested session tags.
4. `PERMISSIONS_DENIED` - federation/role assumption succeeded, but the resulting session was not authorized for the requested API/resource.

`AUTHORIZED` means only that the deliberately small local model accepted the tested request. It is not evidence that a cloud provider issued credentials or allowed a real API call.

## Prerequisites and run command

- Node.js 24.12.0 (a compatible Node.js 22+ runtime is also supported).
- No npm packages, credentials, network access, cloud subscription, or AWS account.

From the repository root:

<div class="language-powershell highlight">

<span id="__span-0-1"><span class="n">`node`</span>` `<span class="n">`labs`</span><span class="p">`/`</span><span class="n">`iam-oidc`</span><span class="p">`/`</span><span class="n">`tests`</span><span class="p">`/`</span><span class="n">`run-tests`</span><span class="p">`.`</span><span class="n">`js`</span>` `</span>

</div>

Expected output:

<div class="language-text highlight">

<span id="__span-1-1">`PASS: 45 IAM/OIDC structural and policy-model evaluations completed. `</span>

</div>

The command exits nonzero on any unexpected decision or structural regression.

## Tested fixture coverage

| Area | Positive fixture | Negative fixtures |
|----|----|----|
| AWS GitHub OIDC | Exact provider, issuer, `sts.amazonaws.com` audience, repository, and `main` branch | Invalid signature; wrong issuer/audience/repository/branch/provider; expired token |
| AWS GitHub environment | Exact repository and `production` environment | Branch subject presented to an environment trust; wrong environment |
| Microsoft Entra federation | Exact GitHub issuer, subject, audience, action, and resource-group scope | Invalid signature; wrong issuer/audience/environment; denied action/scope |
| EKS IRSA | Exact cluster OIDC provider, issuer, audience, namespace, and service account | Wrong cluster issuer/audience/namespace/service account; denied downstream API |
| Third-party `AssumeRole` | Exact vendor role, customer external ID, and constrained session tags | Wrong principal/external ID/tag; extra tag; missing `sts:TagSession` authorization |
| Permission-boundary delegation | Create a role in the delegated path with the approved boundary | Missing/alternate boundary; outside path; boundary removal/replacement |
| Restricted `iam:PassRole` | Exact role, ECS service principal, and task-definition family | Wrong role, destination service, or associated resource |

The readable GitHub subject examples are exact fixture values. A branch subject and an environment subject are alternatives: when a job references an environment, the default subject uses the environment rather than the branch. GitHub also documents immutable owner/repository-ID subject formats for repositories created after July 15, 2026, repositories that opt in, and qualifying renamed/transferred repositories. Inspect the actual token claims for the repository, then make the cloud trust configuration match that format exactly.

## Files and evidence boundary

- `policies/` contains illustrative AWS trust/permissions policies and a Microsoft Entra federated-credential object.
- `fixtures/` contains positive and negative requests. Every mutation declares its expected stage.
- `evaluator.js` implements only the condition operators and policy behavior used by these fixtures.
- `tests/run-tests.js` performs structural assertions and evaluates all fixtures using Node.js built-ins.

The fixture field `"signatureVerified": true` represents output received across a trusted in-process boundary from a real JWT/JWS verifier. Setting the field does not verify a signature. Production integration must discover and pin the intended issuer, select keys by `kid`, validate the allowed algorithm and signature, reject malformed tokens, enforce time and audience rules, and handle key rotation and outage behavior. An attacker-controlled build must not be able to supply or replace the verifier result.

The permission evaluator models explicit deny, identity-policy allow, resource/action matching, selected condition operators, and the intersection with one permissions boundary. It intentionally does not claim full AWS IAM semantics.

## Production validation sequence

1. Inspect provider-issued claims from a protected, non-production workflow or workload and record the exact issuer, audience, and subject format.
2. Validate policy documents with provider tooling and review their deployment plan/change set.
3. Run negative exchanges in a disposable test account/subscription: wrong repository/ref/environment/service account/audience/external ID and unapproved session tags must fail.
4. After a successful exchange, call one explicitly allowed and one explicitly denied API on disposable resources. Capture provider audit evidence without recording bearer credentials.
5. Test revocation/rollback, environment protection, permission-boundary immutability, and `PassRole` changes through the same governed path used in production.

These are documented production-validation steps, not actions performed by this lab.

## AWS simulator limitations

The IAM Policy Simulator is useful for identity policies and one permissions boundary, but AWS documents material limitations: it does not simulate role/user cross-account access, resource-based policies for IAM roles, RCPs, or SCPs that contain conditions. It also does not perform GitHub or EKS OIDC discovery/signature validation, exchange a token through STS, or prove that a role trust policy admits a real federated principal. `SimulatePrincipalPolicy`/`SimulateCustomPolicy` results therefore cannot replace a negative `AssumeRole` or `AssumeRoleWithWebIdentity` test in a disposable AWS account. AWS recommends checking behavior in the live environment after simulation.

IAM Access Analyzer policy validation and external-access findings are valuable static checks, but they likewise do not establish successful end-to-end token verification or downstream authorization.

## Failure modes and limitations

- No cloud resource is created and no AWS, Azure, GitHub, or Kubernetes endpoint is called.
- No JWT/JWS cryptography, JWKS retrieval, certificate path, key rotation, clock-skew policy, replay cache, or bearer-token handling is implemented.
- The evaluator is not a general IAM interpreter. It omits resource policies, SCPs, RCPs, session policies, service-specific authorization, principal-ID transforms, policy variables, `NotAction`/`NotResource`/`NotPrincipal`, and most condition operators.
- Microsoft Entra action/scope evaluation is a pedagogical allow-list, not the Azure RBAC engine. The fixture uses the baseline exact-match federated-credential model, not the separate flexible federated identity credential preview.
- EKS fixtures cover IRSA. EKS Pod Identity uses a different trust model and should have separate tests when selected.
- An external ID mitigates cross-account confused-deputy risk; AWS does not treat it as a secret. It does not replace a narrow principal or least-privilege role policy.
- `iam:PassRole` authorization must be evaluated together with the destination API, the passed role's trust policy, and the passed role's permissions. This lab checks the exact PassRole dimensions and destination service trust, but does not call ECS.

## Cleanup

The test reads tracked JSON and starts one Node.js process. It creates no temporary files, credentials, containers, or cloud resources, so no cleanup is required.

## References

- [AWS: Create a role for OIDC federation, including GitHub conditions](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html)
- [AWS: IAM roles for EKS service accounts](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)
- [AWS: Assign an IAM role to an EKS service account](https://docs.aws.amazon.com/eks/latest/userguide/associate-service-account-role.html)
- [AWS: Access to accounts owned by third parties](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_third-party.html)
- [AWS: Pass session tags in STS](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html)
- [AWS: Permissions boundaries for IAM entities](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)
- [AWS: Grant permission to pass a role](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html)
- [AWS: Policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
- [AWS: IAM Policy Simulator capabilities and limitations](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html)
- [Microsoft: Configure a user-assigned managed identity to trust an external identity provider](https://learn.microsoft.com/entra/workload-id/workload-identity-federation-create-trust-user-assigned-managed-identity)
- [Microsoft: Configure an application to trust an external identity provider](https://learn.microsoft.com/entra/workload-id/workload-identity-federation-create-trust)
- [GitHub: OpenID Connect reference and subject formats](https://docs.github.com/en/actions/reference/security/oidc)
- [GitHub: Configure OIDC in AWS](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws)
- [GitHub: Configure OIDC in Azure](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-azure)
