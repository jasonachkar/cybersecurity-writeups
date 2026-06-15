# 1. Identity & Access Management (IAM)

> Identity is the new perimeter. In cloud environments, the overwhelming majority of impactful incidents trace back to an identity problem: a leaked secret, an over-privileged role, a consented malicious app, or a stolen token. This section covers how to authenticate *workloads* without secrets, how to govern *human* privilege just-in-time, and how to anticipate and detect identity attacks.

**Contents**
- [1.1 Workload identities & machine authentication](#11-workload-identities--machine-authentication)
- [1.2 Enterprise governance & Zero Trust](#12-enterprise-governance--zero-trust)
- [1.3 Identity attack vectors & defenses](#13-identity-attack-vectors--defenses)
- [Best practices summary](#best-practices-summary)
- [Further reading](#further-reading)

---

## 1.1 Workload identities & machine authentication

### The problem with long-lived secrets

A service principal client secret (or an AWS access key) is a **bearer credential**: anyone who holds it *is* the identity. These secrets are:

- **Hard to rotate** — rotation requires coordinated updates across every consumer, so in practice they live for years.
- **Easy to leak** — they end up in CI variables, `.env` files, container layers, Terraform state, and chat messages. Secret scanners (GitGuardian, GitHub secret scanning, `trufflehog`) find them constantly.
- **A lateral-movement multiplier** — a single leaked secret often grants broad, standing access with no device or location binding.

The strategic fix is **workload identity federation (WIF)**: instead of storing a secret, the workload *proves who it is* to its own platform (GitHub, Azure DevOps, Kubernetes, another cloud) and exchanges that proof for a **short-lived** cloud access token.

### OpenID Connect (OIDC), briefly

WIF is built on **OIDC**, which layers identity on top of OAuth 2.0. The key artifact is the **ID token** — a signed JWT whose claims the cloud trusts:

| Claim | Meaning | Why it matters for WIF |
|-------|---------|------------------------|
| `iss` | Issuer (the IdP's URL) | The cloud pins the trusted issuer (e.g., `https://token.actions.githubusercontent.com`). |
| `sub` | Subject (the workload's identity) | The most important claim to scope tightly (e.g., `repo:org/repo:ref:refs/heads/main`). |
| `aud` | Audience (who the token is for) | Must match what the cloud expects, preventing token reuse across services. |
| `exp` / `iat` / `nbf` | Expiry / issued / not-before | Tokens are short-lived; replay window is minimal. |

The cloud validates the JWT signature against the issuer's **JWKS** (published at `/.well-known/openid-configuration` → `jwks_uri`), then checks `iss`/`sub`/`aud` against a configured **federated credential**. No secret is ever stored.

```
  GitHub Actions runner                 Azure AD (Entra ID)              Azure Resource
  ─────────────────────                ────────────────────             ───────────────
        │                                      │                              │
   (1)  │  request OIDC token (aud=api://AzureADTokenExchange)               │
        │─────────────► GitHub OIDC provider   │                              │
        │◄───────────── signed JWT (sub=repo:org/repo:environment:prod)      │
        │                                      │                              │
   (2)  │  POST /oauth2/v2.0/token             │                              │
        │  grant_type=client_credentials       │                              │
        │  client_assertion=<the JWT>          │                              │
        │─────────────────────────────────────►│                              │
        │                                      │ validate sig via JWKS,       │
        │                                      │ match iss/sub/aud to a        │
        │                                      │ federated credential          │
        │◄─────────────────────────────────────│                              │
        │   short-lived Azure access token (≈1h)│                              │
   (3)  │───────────────────────────────────────────────────────────────────►│
        │                          call ARM / data plane with bearer token    │
```

### Hands-on: GitHub Actions → Azure with WIF (no secrets)

**Step 1 — Create an app registration / service principal** and grant it *only* the RBAC it needs (e.g., `Contributor` scoped to one resource group, never subscription Owner).

**Step 2 — Register a federated credential** mapping GitHub's OIDC token to the app. Note the tight `subject`:

```bash
# Federate a specific environment ("prod") of one repo. Nothing else can mint a token.
az ad app federated-credential create \
  --id "$APP_OBJECT_ID" \
  --parameters '{
    "name": "github-myorg-myrepo-prod",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:myorg/myrepo:environment:prod",
    "audiences": ["api://AzureADTokenExchange"]
  }'
```

Common `subject` formats for GitHub:

| Trigger | `subject` value |
|---------|-----------------|
| A branch | `repo:ORG/REPO:ref:refs/heads/main` |
| A tag | `repo:ORG/REPO:ref:refs/tags/v1.2.3` |
| A GitHub **Environment** (recommended) | `repo:ORG/REPO:environment:prod` |
| A pull request | `repo:ORG/REPO:pull_request` |

**Step 3 — The workflow** requests the token and logs in. The crucial line is `permissions: id-token: write`:

```yaml
name: deploy
on:
  push:
    branches: [ main ]

permissions:
  id-token: write      # allow the runner to request an OIDC token
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: prod   # binds to the federated subject above
    steps:
      - uses: actions/checkout@v4

      - name: Azure login (federated, secretless)
        uses: azure/login@v2
        with:
          client-id: ${{ vars.AZURE_CLIENT_ID }}      # not a secret
          tenant-id: ${{ vars.AZURE_TENANT_ID }}
          subscription-id: ${{ vars.AZURE_SUBSCRIPTION_ID }}
          # NOTE: no client-secret. Login uses the OIDC token exchange.

      - name: Deploy
        run: az group list -o table
```

> **Result:** there is no secret to leak, rotate, or steal from CI. The credential is valid only for that repo's `prod` environment, only for the lifetime of the run, and only with the RBAC you scoped.

### Managed identities (inside Azure)

For workloads *running in Azure* (VMs, App Service, Container Apps, AKS, Functions), prefer **managed identities** — Azure manages the credential lifecycle entirely:

- **System-assigned:** tied 1:1 to a resource's lifecycle; deleted with it. Good for single-purpose resources.
- **User-assigned:** a standalone identity you can attach to many resources; good for shared identity and pre-provisioning RBAC.

Code retrieves tokens via `DefaultAzureCredential` (Azure SDK) or IMDS — again, no secret in the app.

### Kubernetes: Microsoft Entra Workload ID

AAD Pod Identity is deprecated; the replacement is **Microsoft Entra Workload ID** (`azure-workload-identity`), which uses the **same OIDC federation** mechanism:

1. The AKS cluster exposes an **OIDC issuer**.
2. A Kubernetes **ServiceAccount** is annotated with an Azure client ID.
3. A **federated credential** trusts `system:serviceaccount:<namespace>:<sa-name>` for that issuer.
4. The pod's projected SA token is exchanged for an Azure token. No secrets in the pod.

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: workload-sa
  namespace: payments
  annotations:
    azure.workload.identity/client-id: "<USER_ASSIGNED_CLIENT_ID>"
```

### Cross-cloud / multi-cloud federation

The same pattern generalizes — the cloud trusts an external OIDC issuer:

- **AWS:** `AssumeRoleWithWebIdentity` via an IAM **OIDC identity provider** and a role trust policy that pins `token.actions.githubusercontent.com:sub`. Always constrain both `:sub` (repo/branch) **and** `:aud` (`sts.amazonaws.com`) in the trust policy — a wildcard `sub` lets *any* repo assume the role.
- **GCP:** **Workload Identity Federation** with a workload identity pool + provider, mapping `attribute.repository` to allow only specific repos.
- **Azure ↔ AWS/GCP:** federate Azure apps against AWS/GCP IdPs (and vice versa) for genuine multi-cloud automation without cross-cloud secrets.

### Common misconfigurations & failure modes

| Misconfiguration | Why it's dangerous | Fix |
|------------------|--------------------|-----|
| **Overly broad `subject`** (e.g., `repo:org/repo:*` or only pinning the repo, not the branch/environment) | Any workflow — including one from a malicious PR — can mint a production token. | Pin to a specific branch or, better, a protected **Environment** with required reviewers. |
| **Missing/loose `aud` validation** (AWS especially) | Tokens minted for another service can be replayed. | Always require the exact expected audience in the trust policy/federated credential. |
| **`pull_request` subject with deploy permissions** | Forked-PR or untrusted contributor code can trigger privileged deploys. | Never grant deploy roles to `pull_request` subjects; use `environment` + branch protection. |
| **Over-privileged backing identity** | WIF removes the *secret* but not *standing privilege*; a compromised pipeline still has whatever RBAC the SP holds. | Scope RBAC to least privilege (resource-group, specific roles), separate per environment. |
| **Forgotten/leftover federated credentials** | Stale trust to old repos/branches becomes an unmonitored door. | Periodically review and prune federated credential definitions. |

---

## 1.2 Enterprise governance & Zero Trust

Large organizations span many subscriptions/accounts and management groups. The governance goal is **least privilege, granted just-in-time, verified continuously** — the essence of **Zero Trust** (NIST SP 800-207): *never trust, always verify, assume breach.*

### Privileged Identity Management (PIM) — including PIM for Groups

Standing privilege is the root of most escalation. **PIM** makes privileged roles **eligible** rather than **active**: a user must *activate* the role on demand, subject to controls.

- **PIM for Azure roles & Entra roles:** time-bound activation, MFA on activation, justification, and approval workflows.
- **PIM for Groups:** instead of assigning dozens of roles to a user, make them *eligible* for membership in a **role-assignable group** that holds the roles. Activating membership grants all the group's roles at once — drastically reducing assignment sprawl and making reviews tractable.

**Recommended PIM configuration:**

- Activation duration **1–4 hours**, not days.
- **Require approval** for the most sensitive roles (Owner, Global Administrator, Privileged Role Administrator).
- **Require MFA / authentication strength** on activation (phishing-resistant where possible).
- **Require justification** and ticket reference.
- **Access reviews** quarterly for eligibility; auto-remove unused eligibility.
- **No permanent active assignments** for Tier-0 roles — eligibility only.

### Conditional Access (CA) — layered policy design

Conditional Access is the Zero Trust policy engine for Entra ID. Evaluate **signals** (user/sign-in risk, device compliance, location, client app, authentication strength) and apply **grant/session controls**. Design in **layers**, from broadest to most specific:

```
Layer 0 (baseline, all users):     Block legacy authentication (no modern auth = no access)
Layer 1 (all users):               Require MFA for all cloud apps
Layer 2 (admins / privileged):     Require phishing-resistant MFA + compliant/Hybrid-joined device
Layer 3 (risk-based):              If sign-in risk = High  -> block; Medium -> require step-up MFA
                                    If user risk   = High  -> require secure password change
Layer 4 (app/data-specific):       For finance/HR apps -> require compliant device + approved app
Layer 5 (session):                 Sign-in frequency limits; no persistent browser for unmanaged devices
```

**Design principles & guardrails:**

- **Always keep break-glass accounts excluded** from CA (two cloud-only emergency accounts, long random passwords in a vault, FIDO2 keys, heavily monitored). Locking yourself out of the tenant is a real and common failure mode.
- **Use Report-only mode first** to measure impact before enforcing.
- **Block legacy authentication** explicitly — it bypasses MFA entirely and is a top initial-access vector.
- **Prefer authentication strength** (e.g., require FIDO2/passkey or certificate) over generic "require MFA" for privileged scenarios.
- **Restrict the device code flow** and other "other clients" grant types for users who don't need them (a common consent/phishing vector — see §1.3).

### Tenant & subscription isolation

- Consider **separate Entra ID tenants** for production vs. non-production where blast-radius isolation justifies the operational overhead; otherwise, isolate via **management group hierarchy** and subscription boundaries.
- Use **cross-tenant access settings** to control inbound/outbound B2B collaboration; default-deny unknown tenants; require MFA/compliant device claims to be **trusted** from partner tenants only where warranted.
- Enforce structure with **Azure Policy** at the management-group level (allowed regions, required tags, deny public IPs, require diagnostic settings — see Section 4).

---

## 1.3 Identity attack vectors & defenses

Modern attackers rarely "crack passwords." They **steal tokens** or **abuse consent**, often bypassing MFA entirely.

### Token theft & replay (incl. PRT and AiTM)

- **Refresh / Primary Refresh Token (PRT) theft:** malware on an endpoint extracts the Windows PRT or browser refresh/session tokens and replays them from attacker infrastructure, inheriting the user's authenticated session — **including MFA** — because the token already represents a completed MFA.
- **Adversary-in-the-Middle (AiTM):** reverse-proxy phishing kits (e.g., Evilginx-style) sit between the user and the real IdP, relay credentials *and* the MFA prompt, and capture the resulting **session cookie**. This defeats traditional (non-phishing-resistant) MFA.

**Defenses:**
1. **Phishing-resistant MFA** (FIDO2/passkeys, Windows Hello for Business, certificate-based auth) — the cryptographic binding can't be relayed by a proxy.
2. **Token Protection / token binding** (Entra) — binds the refresh token/session to the device so a stolen token is useless elsewhere.
3. **Continuous Access Evaluation (CAE)** — near-real-time revocation: when risk is detected or the user is disabled, access is cut within minutes instead of waiting for token expiry.
4. **Conditional Access** requiring **compliant devices** for sensitive apps — a stolen token from an unmanaged device fails policy.

### Consent phishing (illicit consent grants)

A malicious **multi-tenant OAuth app** requests high-privilege Microsoft Graph scopes (e.g., `Mail.Read`, `Files.ReadWrite.All`, `offline_access`). A tricked user clicks **Accept**, and the attacker gets **persistent, MFA-independent** access via the granted OAuth token — no password needed, survives password resets.

**Defenses:**
1. **Restrict user consent** to verified publishers and low-impact, well-understood permissions only; route everything else through an **admin consent workflow**.
2. **Publisher verification** — surface and require verified publisher status.
3. **App governance** (Defender for Cloud Apps) to detect risky/over-privileged OAuth apps and anomalous app behavior.
4. **Periodically review and revoke** unused enterprise app grants and delegated permissions.

### OAuth / OIDC implementation misconfiguration

(See the companion writeup [`docs/research/oauth-misconfigurations`](../oauth-misconfigurations/README.md) for depth.) Briefly: overly broad redirect URIs, missing `state`/`nonce` validation, implicit flow, and excessive scopes lead to token leakage and CSRF/code-injection. **Mitigations:** exact-match redirect URIs, mandatory PKCE (S256), `state`+`nonce` validation, least-scope requests, short-lived tokens.

### Service principal & key theft

Hard-coded client secrets in repos, pipeline variables, or container images are prime targets and are continuously scanned for by adversaries. **Mitigation:** migrate to **workload identity federation** (§1.1) and managed identities; where secrets are unavoidable, store them in Key Vault with rotation and access logging (see Section 3).

### Turning control failures into detections

Every defense above has a telemetry signal. Wire these into the SIEM (Section 4):

| Attack | Primary signal(s) | Sentinel table |
|--------|-------------------|----------------|
| AiTM / token replay | Impossible travel, unfamiliar sign-in properties, token issuer anomalies | `SigninLogs`, `AADUserRiskEvents` |
| Consent phishing | New OAuth grant to high-privilege scopes | `AuditLogs` (Category `ApplicationManagement`, "Consent to application") |
| PIM abuse | Activation outside business hours; activation immediately followed by resource changes | `AuditLogs` (PIM) joined to `AzureActivity` |
| SP secret abuse | Non-interactive sign-ins from new IPs/ASNs for a service principal | `AADServicePrincipalSignInLogs` |

---

## Best practices summary

- **Eliminate secrets:** WIF/OIDC for CI/CD and cross-cloud; managed identities inside Azure; Entra Workload ID for Kubernetes.
- **Scope federation tightly:** pin `sub` to a repo + branch/environment and validate `aud`; prune stale federated credentials.
- **Least privilege, just-in-time:** PIM for roles and groups; no standing Tier-0 access; approvals, MFA, short activations, access reviews.
- **Layered Conditional Access:** block legacy auth; phishing-resistant MFA for admins; risk-based step-up; break-glass exclusions; report-only first.
- **Beat token theft & consent abuse:** phishing-resistant MFA, Token Protection, CAE, restricted user consent + admin consent workflow, app governance.
- **Instrument everything:** route identity telemetry to the SIEM and build the detections in Section 4.

---

## Further reading

- NIST SP 800-207, *Zero Trust Architecture* — <https://csrc.nist.gov/pubs/sp/800/207/final>
- NIST SP 800-63B, *Digital Identity Guidelines — Authentication* — <https://pages.nist.gov/800-63-3/sp800-63b.html>
- Microsoft — *Configure a federated identity credential* — <https://learn.microsoft.com/entra/workload-id/workload-identity-federation-create-trust>
- GitHub — *About security hardening with OpenID Connect* — <https://docs.github.com/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect>
- Microsoft Entra Workload ID — <https://learn.microsoft.com/entra/workload-id/workload-identities-overview>
- Microsoft — *Conditional Access design principles* — <https://learn.microsoft.com/entra/identity/conditional-access/plan-conditional-access>
- Microsoft — *Privileged Identity Management* — <https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-configure>
- AWS — *Configure OIDC for GitHub Actions* — <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html>

---

[← Back to overview](./README.md) · [Next: DevSecOps & Pipeline Hardening →](./devsecops-pipeline-hardening.md)
