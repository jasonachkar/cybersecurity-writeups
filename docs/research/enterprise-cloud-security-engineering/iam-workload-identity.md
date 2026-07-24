# 1. Identity & Access Management (IAM)

> **Evidence status:** This is a broad legacy survey that has been corrected for the
> workload-identity claims and examples below. The cloud snippets remain
> **illustrative** and were not deployed. Exact trust behavior is **partially tested**
> by the dependency-free
> [`labs/iam-oidc`](../../../labs/iam-oidc/README.md) fixture lab. Product guidance
> outside that lab still requires tenant/account-specific review.

Identity compromise is a common path to cloud impact: leaked secrets,
over-privileged roles, malicious application consent, and stolen tokens can all turn
an initial foothold into control-plane access. This section explains how to
authenticate workloads without long-lived cloud secrets, govern human privilege
just-in-time, and detect identity attacks.

**Contents**

- [1.1 Workload identities & machine authentication](#11-workload-identities-machine-authentication)
- [1.2 Enterprise governance & Zero Trust](#12-enterprise-governance-zero-trust)
- [1.3 Identity attack vectors & defenses](#13-identity-attack-vectors-defenses)
- [Best practices summary](#best-practices-summary)
- [Further reading](#further-reading)

---

## 1.1 Workload identities & machine authentication

### The problem with long-lived secrets

A service-principal client secret or AWS access key is a bearer credential: a caller
that obtains it can use it within the credential's permissions and other applicable
controls. Long-lived credentials create recurring engineering risks:

- **Rotation is coordinated work.** Every consumer needs a safe update/rollback path,
  so poorly owned credentials can remain valid far longer than intended.
- **Copies proliferate.** Secrets can reach CI variables, `.env` files, container
  layers, Terraform state, tickets, and chat.
- **Standing privilege persists.** Rotation changes credential material; it does not
  reduce an over-privileged identity's authorization.

The strategic replacement for supported external workloads is workload identity
federation (WIF): the workload obtains an assertion from its platform (for example,
GitHub or Kubernetes) and exchanges that assertion for a short-lived cloud access
token. WIF removes the need to provision a long-lived cloud client secret to the
workload. The platform assertion and resulting bearer token are still sensitive and
must be protected.

### OpenID Connect (OIDC), briefly

GitHub Actions and Kubernetes workload federation commonly use a signed OIDC JWT. The
cloud first authenticates the assertion against a configured issuer/provider and then
evaluates the configured trust relationship.

| Claim | Meaning | Why it matters for WIF |
| --- | --- | --- |
| `iss` | Issuer URL | Selects the configured identity provider and its verification material. |
| `sub` | Workload subject | Binds trust to an exact repository/ref/environment or Kubernetes service account. |
| `aud` | Intended audience | Prevents an assertion minted for another exchange from being accepted here. |
| `exp` / `iat` / `nbf` | Expiry / issued / not-before | Bounds when the assertion may be accepted. |

Issuer/JWKS discovery and signature verification authenticate the claim set; they do
not authorize every authenticated subject. The cloud must also match the exact
issuer/audience/subject trust and then separately evaluate the resulting principal's
permissions.

```text
  GitHub Actions runner                 Microsoft Entra ID               Azure resource
  ─────────────────────                ────────────────────             ──────────────
        │                                      │                              │
   (1)  │ request GitHub OIDC token            │                              │
        │◄──────── signed JWT assertion         │                              │
        │           iss / aud / sub             │                              │
   (2)  │ token exchange with client assertion │                              │
        │─────────────────────────────────────►│                              │
        │                                      │ verify signature/claims;     │
        │                                      │ exact-match federated trust  │
        │◄─────────────────────────────────────│                              │
        │        short-lived Azure access token│                              │
   (3)  │───────────────────────────────────────────────────────────────────►│
        │                         resource API performs authorization         │
```

### Keep four decisions separate

Do not report all failures as “OIDC failed”:

1. **Signature invalid:** no claim is trusted.
2. **Signature valid but claims rejected:** issuer, audience, or token lifetime is
   unacceptable.
3. **Claims accepted but trust rejected:** the exact subject/principal, external ID,
   or requested session tags do not satisfy the federated credential/role trust.
4. **Role/token issued but permissions denied:** the session exists, but RBAC/IAM,
   resource policy, boundary/session policy, organization guardrail, or
   service-specific check denies the requested API/resource.

The [offline IAM/OIDC lab](../../../labs/iam-oidc/README.md) reproduces every stage and
tests exact AWS GitHub branch/environment trust, Microsoft Entra federation, EKS IRSA,
third-party external ID/session tags, permission-boundary mutation, and restricted
`iam:PassRole`. Its `"signatureVerified": true` field represents a trusted verifier
adapter result; it does not perform cryptographic verification or a live cloud
exchange.

### Hands-on design: GitHub Actions to Azure with WIF

The following commands and workflow are **illustrative**. Use a disposable tenant/
subscription to perform the negative exchanges documented in the lab README before
production use.

**Step 1 — Create an application/service principal or supported managed identity.**
Grant only the Azure RBAC data/control-plane actions the workload needs at the narrow
resource scope. A broad built-in role such as Contributor is not a default
recommendation merely because it is convenient.

**Step 2 — Register a federated credential** that exactly maps the GitHub assertion to
the Azure identity:

```bash
# Illustrative: substitute a non-production application object ID.
az ad app federated-credential create \
  --id "<app-object-id>" \
  --parameters '{
    "name": "github-example-security-cloud-controls-production",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:example-security/cloud-controls:environment:production",
    "audiences": ["api://AzureADTokenExchange"]
  }'
```

Baseline Microsoft Entra federated credentials exact-match `issuer`, `subject`, and
the single configured audience. Wildcards are not supported in that baseline model.
A correctly signed token for another repository or environment must not match this
credential.

Common readable GitHub `sub` formats include:

| Job context | Example subject |
| --- | --- |
| Branch (no environment) | `repo:ORG/REPO:ref:refs/heads/main` |
| Tag (no environment) | `repo:ORG/REPO:ref:refs/tags/v1.2.3` |
| GitHub environment | `repo:ORG/REPO:environment:production` |
| Pull request (no environment) | `repo:ORG/REPO:pull_request` |

A branch and environment are not simultaneously encoded in the default subject:
referencing an environment selects the environment form. GitHub also documents
immutable owner/repository-ID subject formats for repositories created after
July 15, 2026, repositories that opt in, and qualifying renames/transfers. Inspect
the actual token and configure the exact format your repository emits.

**Step 3 — Request OIDC permission and use a full-SHA-pinned login action:**

```yaml
name: deploy
on:
  push:
    branches: [main]

permissions:
  id-token: write
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - name: Check out reviewed source
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with:
          persist-credentials: false

      - name: Exchange GitHub OIDC assertion for Azure access
        uses: azure/login@a457da9ea143d694b1b9c7c869ebb04ebe844ef5 # v2
        with:
          client-id: ${{ vars.AZURE_CLIENT_ID }}
          tenant-id: ${{ vars.AZURE_TENANT_ID }}
          subscription-id: ${{ vars.AZURE_SUBSCRIPTION_ID }}

      - name: Exercise one explicitly allowed read
        run: az group show --name cloud-controls-production --output none
```

`id-token: write` allows the job to request a GitHub OIDC token; it does not itself
grant Azure access. The federated credential and Azure authorization remain decisive.
This pattern removes a stored Azure client secret from the workflow, but a compromised
trusted workflow can still request and misuse short-lived bearer tokens within the
identity's permissions. Protect the referenced environment, allowed deployment
branches, workflow changes, action pins, and backing identity.

### Managed identities inside Azure

For supported workloads running in Azure (for example, VMs, App Service, Container
Apps, AKS, or Functions), prefer managed identities:

- **System-assigned:** lifecycle-coupled to one Azure resource.
- **User-assigned:** a standalone identity that can be attached to supported
  resources and pre-provisioned with RBAC.

Applications can request tokens through the supported Azure SDK credential chain or
managed-identity endpoint without embedding a client secret. The returned access
token remains a bearer token and should not be logged or persisted.

### Kubernetes: Microsoft Entra Workload ID

Microsoft Entra Workload ID replaces the retired AAD Pod Identity pattern for
supported AKS workload federation:

1. The AKS cluster exposes an OIDC issuer.
2. A Kubernetes service account is associated with an Azure client ID.
3. A federated credential trusts the exact cluster issuer and
   `system:serviceaccount:<namespace>:<service-account>` subject.
4. A projected service-account token is exchanged for an Azure token.

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: workload-sa
  namespace: payments
  annotations:
    azure.workload.identity/client-id: "<user-assigned-managed-identity-client-id>"
```

Restrict who may create/patch pods and service accounts, because that Kubernetes
authority can confer the workload's cloud identity. Disable automounting service
account tokens where they are unnecessary.

### Cross-cloud federation

The pattern generalizes, but each provider implements its own trust language:

- **AWS GitHub OIDC:** `AssumeRoleWithWebIdentity` against an IAM OIDC provider and a
  role trust policy with exact `token.actions.githubusercontent.com:aud` and `:sub`
  conditions. Broad subject patterns delegate to every matching workflow identity,
  not literally every GitHub repository.
- **AWS EKS IRSA:** exact cluster OIDC provider, `sts.amazonaws.com` audience, and
  `system:serviceaccount:<namespace>:<service-account>` subject.
- **GCP Workload Identity Federation:** workload identity pool/provider plus attribute
  conditions/mappings that constrain the intended repository/workload.
- **Microsoft Entra federation:** exact baseline issuer/audience/subject matching for
  applications or user-assigned managed identities in supported scenarios.

Do not infer that successful federation grants useful resource access. Cloud IAM/RBAC
still evaluates the exchanged principal.

### AWS delegation details often missed

- For a third-party service assuming customer roles, require the exact vendor
  principal and a unique vendor-managed customer external ID. AWS does not treat the
  external ID as a secret; it mitigates cross-account confused-deputy risk.
- If a caller supplies AWS session tags, authorize `sts:TagSession` in the trust
  policy and restrict both `aws:TagKeys` and `aws:RequestTag/<key>`.
- A permission boundary limits maximum identity-policy permissions; it grants
  nothing. Delegated administrators must be required to create roles with the
  approved boundary and denied permission to remove or replace it.
- Restrict `iam:PassRole` to exact role ARNs/paths and, where supported and tested,
  `iam:PassedToService` and `iam:AssociatedResourceArn`. Review the destination API,
  passed role trust policy, and passed role permissions together.

AWS's IAM Policy Simulator does not prove a workload-identity exchange. AWS documents
that it does not simulate role/user cross-account access, resource-based policies for
IAM roles, RCPs, or SCPs with conditions. It also does not validate a GitHub/EKS token
signature or call STS. Use it for supported identity-policy/boundary checks, then
perform allowed and denied exchanges in a disposable account.

### Common misconfigurations and failure modes

| Misconfiguration | Risk | Correction |
| --- | --- | --- |
| Broad or copied `sub` pattern | Every matching workflow identity can reach the trust boundary; copied formats may not match current immutable subjects. | Inspect actual claims and exact-match the intended repository/ref/environment or immutable IDs. |
| Missing/loose audience check | An assertion intended for another exchange may be accepted if the provider/trust configuration permits it. | Require the provider-specific exact audience. |
| Privileged pull-request subject | Untrusted code may reach a privileged job when event, token-permission, workflow, and environment controls are unsafe. | Keep PR validation unprivileged; put deployment behind a separately protected branch/environment workflow. |
| Over-privileged backing identity | WIF removes a stored secret, not standing authorization. | Scope per environment and resource; test an explicit allowed and denied API. |
| Stale federated credentials | Old repositories/branches/environments remain trusted. | Inventory owners and expiry/review dates; remove stale trust through review. |
| Boundary can be removed/replaced | Delegated administrators can escape the intended maximum permission set. | Constrain creation and explicitly deny boundary mutation for the delegated role. |

---

## 1.2 Enterprise governance & Zero Trust

Large organizations span subscriptions/accounts, management groups, and tenants. The
governance goal is least privilege, granted just in time where appropriate, with
continuous verification and evidence.

### Privileged Identity Management (PIM), including PIM for Groups

PIM can make supported privileged assignments eligible rather than continuously
active. Activation controls vary by role/resource/license and should be validated in
the target tenant.

- Use time-bounded activation for sensitive Entra and Azure roles.
- Require approval for selected high-impact roles where an independent approver and
  emergency path are operationally sustainable.
- Require an appropriate authentication strength and justification/ticket reference.
- Review eligibility and remove access that no longer has an owner or business need.
- Avoid permanent active Tier-0 assignments except documented emergency access.

PIM for Groups can centralize eligibility for group membership/ownership. Treat a
role-assignable group's membership controls as part of the same privilege boundary as
the roles assigned to it.

### Conditional Access (CA): layered policy design

Conditional Access evaluates supported identity/device/risk/application signals and
applies grant/session controls. A typical design may include:

```text
Baseline:                  block legacy authentication where supported
Broad user protection:     require an approved MFA/authentication strength
Privileged users:          phishing-resistant authentication + managed device
Risk policies:             block or remediate according to validated risk appetite
Sensitive applications:   stronger device/client/session requirements
```

Roll out in report-only mode, inspect actual impact, exclude only controlled emergency
accounts, and validate unsupported/authentication-protocol cases. Keep at least two
cloud-only emergency-access accounts with independently protected credentials,
purpose-specific monitoring, and rehearsed use/recovery.

### Tenant and subscription isolation

- Use separate tenants only when the blast-radius/compliance benefit justifies the
  added identity, governance, and incident-response complexity.
- Within a tenant, use management groups, subscriptions, resource groups, Azure Policy,
  RBAC, and network/data boundaries according to their documented semantics.
- Configure cross-tenant access deliberately; do not trust partner MFA/device claims
  without an explicit partner decision and ongoing review.

---

## 1.3 Identity attack vectors & defenses

### Token theft and adversary-in-the-middle attacks

Endpoint malware and adversary-in-the-middle phishing can steal bearer/session tokens
after authentication. A completed MFA event does not make a stolen bearer token
unusable.

Defenses include:

1. phishing-resistant authentication for privileged/high-risk use;
2. supported token-protection/device-binding controls for compatible clients and
   resources;
3. Conditional Access and Continuous Access Evaluation where supported;
4. endpoint, browser, identity, and workload protections that reduce token theft;
5. rapid session/token revocation and investigation procedures.

Do not promise immediate universal revocation: propagation and support depend on token
type, client, resource, and event.

### Consent phishing and illicit application grants

A malicious or compromised OAuth application can request delegated/application
permissions and retain useful access according to the grant and token lifetimes.
Password changes alone do not necessarily remove an application consent grant.

Defenses include:

1. restrict user consent to a reviewed low-risk policy and route other requests
   through an admin-consent workflow;
2. treat publisher verification as one signal, not proof of application safety;
3. monitor risky applications, grants, credential additions, and anomalous use;
4. review/revoke unused grants and remove compromised app credentials/sessions.

### OAuth/OIDC implementation misconfiguration

See the companion
[`docs/research/oauth-misconfigurations`](../oauth-misconfigurations/README.md).
Use exact redirect-URI matching except the narrowly defined native-app loopback port
exception, authorization code plus PKCE (`S256`), transaction-bound `state`, OIDC
`nonce` and ID-token validation, least scopes, and explicit issuer/audience/token-type
checks.

### Turning control failures into detections

Telemetry names and availability vary by license, resource, and connector. Candidate
signals include:

| Attack/control failure | Candidate signal | Example Entra/Sentinel table |
| --- | --- | --- |
| Token replay/AiTM | unfamiliar sign-in properties, risk detections, session anomalies | `SigninLogs`, risk-event tables |
| Consent abuse | new high-impact OAuth grant or application credential | `AuditLogs`, service-principal sign-in logs |
| PIM abuse | unusual activation followed by control-plane change | `AuditLogs` joined to `AzureActivity` |
| Workload identity abuse | new location/workload pattern or failed federation | service-principal/workload identity sign-in logs |

Validate exact schemas and retention in the target workspace before publishing a
detection as runnable.

---

## Best practices summary

- Prefer WIF/OIDC for supported CI/CD and external workloads; use managed identities
  inside Azure where supported.
- Exact-match the issuer, audience, and actual current subject format; protect the
  trusted repository branch/environment and its workflow changes.
- Keep token authentication, federated trust, and resulting authorization as separate
  tests with separate evidence.
- For AWS, test external ID/session tags, boundary immutability, and restricted
  PassRole—not only a happy-path OIDC policy.
- Use just-in-time privileged activation and layered Conditional Access with controlled
  emergency access and report-only rollout.
- Protect, monitor, and rapidly revoke bearer/session tokens and application grants.
- Route identity telemetry to the SIEM only after validating source, schema, and
  retention.

---

## Further reading

- NIST SP 800-207, *Zero Trust Architecture* —
  <https://csrc.nist.gov/pubs/sp/800/207/final>
- Microsoft, configure a federated identity credential —
  <https://learn.microsoft.com/entra/workload-id/workload-identity-federation-create-trust>
- Microsoft, configure user-assigned managed-identity federation —
  <https://learn.microsoft.com/entra/workload-id/workload-identity-federation-create-trust-user-assigned-managed-identity>
- GitHub, OpenID Connect reference and subject formats —
  <https://docs.github.com/en/actions/reference/security/oidc>
- GitHub, configure OIDC in Azure —
  <https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-azure>
- AWS, create a role for OIDC federation —
  <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html>
- AWS, IAM roles for EKS service accounts —
  <https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html>
- AWS, third-party role access and external IDs —
  <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_third-party.html>
- AWS, STS session tags —
  <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html>
- AWS, permission boundaries —
  <https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html>
- AWS, grant permission to pass a role —
  <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html>
- AWS, IAM Policy Simulator capabilities and limitations —
  <https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html>
- Microsoft, Conditional Access planning —
  <https://learn.microsoft.com/entra/identity/conditional-access/plan-conditional-access>
- Microsoft, Privileged Identity Management —
  <https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-configure>

---

[← Back to overview](./README.md) ·
[Next: DevSecOps & Pipeline Hardening →](./devsecops-pipeline-hardening.md)
