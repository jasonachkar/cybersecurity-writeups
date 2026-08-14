---
title: "Attack Path Analysis: Preconditions, Reachability and Evidence-Backed Control Breaks"
type: "threat-intel"
tags:
  - threat-intel
  - attack
  - path
  - analysis
date: "2026-07-25"
lastReviewed: "2026-07-25"
readingTime: 10
reviewStatus: "partially-verified"
validatedAgainst:
  - "GitHub Actions OpenID Connect security model — https://docs.github.com/en/actions/concepts/security/openid-connect"
  - "GitHub OIDC token claims and subject customization — https://docs.github.com/en/actions/reference/security/oidc"
  - "AWS IAM policy evaluation logic — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html"
  - "AWS IAM OIDC identity providers and role trust — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html"
  - "AWS STS `AssumeRoleWithWebIdentity` — https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html"
  - "Kubernetes service-account workload identity — https://kubernetes.io/docs/concepts/security/service-accounts/"
sourceQuality: "primary-sources-reviewed"
implementationStatus: "illustrative"
reviewIntervalDays: 90
---

# Attack Path Analysis: Preconditions, Reachability and Evidence-Backed Control Breaks

An attack path is a conditional argument, not a line in a graph. Each edge needs a starting capability, reachable target, accepted credential or trust relationship, satisfied policy conditions, and a consequential action. Missing evidence leaves an unknown edge; it does not justify colouring the edge exploitable.

## The core decision

Prioritize paths by preconditions you've actually verified, impact, and how many independent, good controls would have to fail for it to go through. For each edge, name the exact principal or asset, credential, network route, identity transition, policy conditions, runtime requirement, data source, and the checkpoint that's supposed to stop it. Then test the case that should actually break the edge. Recompute after changes, and treat how stale the graph is as part of your confidence, not an afterthought.

## Scope and non-goals

This reference specifies three representative paths:

1. CI workflow → federated cloud role → sensitive deployment;
2. compromised Kubernetes workload → workload identity → cloud data plane; and
3. cross-tenant application flaw → data-store authorization boundary.

These are design scenarios, not incident claims. The article does not assert a vulnerable named organization, a successful container escape, a production tenant breach, or a complete scanner. It does not treat a CVE, ATT&CK technique, IAM allow, route, or graph edge as proof of exploitability.

## Graph reachability versus exploitability

| Question | Evidence | Common overstatement |
|----|----|----|
| Network reachability | Resolved destination, route, DNS, security group/NACL/firewall/CNI decision, listener and protocol | “Same VPC/cluster means reachable” |
| Identity reachability | Credential issuance/presence, issuer, audience, subject, trust and session conditions | “Workload can get a token, therefore it can use the target” |
| Authorization reachability | Identity/resource/session/boundary/SCP policy and application object decision | “An allow statement proves access” |
| Exploitability | Vulnerable behavior, controllable input, required state/version/configuration and successful negative/positive test | “A route, CVE or technique ID proves compromise” |
| Impact | Specific action/resource/data and recovery consequence | “Cloud access means administrator” |

Model network and identity reachability separately. A resource can be routable but reject identity, or an identity can be authorized while no route exists. Application data APIs may be reachable through an authorized service while the caller is still denied at tenant/object policy.

## Evidence, time and unknowns

Attach provenance and observation time to every node and edge:

- **Configuration evidence:** workflow at commit/digest, IAM and resource policies, trust relationships, deployment manifest, service account, route tables, security rules, database policies.
- **Runtime evidence:** resolved artifact digest, issued token claims, pod UID, live route/listener, CloudTrail or audit event, admission decision, application authorization decision.
- **Conditional evidence:** branch/environment, OIDC subject/audience, principal/session tags, source ARN/account/VPC endpoint, time, MFA, object/tenant state.
- **Freshness:** collection timestamp, maximum age, change event and last successful verification.
- **Unknowns:** data not visible in IaC, generated policies, runtime mutation, emergency exceptions, cached permissions, manual console changes and provider-side state.

IaC shows intended managed configuration, not all live state. Graph data can become stale between collection and response. Conditional policies cannot be flattened to an unconditional allow without evaluating the request context. Record “unknown” rather than assuming allow or deny.

## Scenario 1: CI workflow → federated cloud role → sensitive deployment

**Initial foothold**

Attacker can modify or execute a specific repository workflow context, or controls a dependency/action that executes in that context. A generic repository read token is insufficient.

**Required preconditions**

The job receives an OIDC token; the cloud trust policy accepts its issuer, exact audience and subject/claim conditions; the job can request the target role; session/boundary/SCP policy permits deployment; environment approvals do not block; and the deployment target accepts the role's action.

**Edge-by-edge path**

1. **Workflow control → OIDC request:** job has `id-token: write` and reaches the token endpoint. Enforcement: workflow permissions and protected workflow review.
2. **OIDC token → role session:** AWS validates the GitHub issuer and trust-policy audience/subject conditions. Enforcement: role trust policy.
3. **Role session → deployment API:** identity policy, permission boundary, session policy, SCP and resource policy permit the exact action/resource/conditions. Enforcement: IAM policy evaluation.
4. **Deployment API → sensitive runtime:** artifact, environment and target controls accept the change. Enforcement: protected environment, signer/provenance policy, deployment service and admission controls.

**Evidence source**

Workflow file at reviewed commit; action pins; environment rules; OIDC token claims from an authorized diagnostic run; role trust/permission/boundary/SCP/resource policies; CloudTrail STS and deployment events; artifact digest and admission/deployment record.

**Preventive controls**

Untrusted PR jobs without credentials; minimal workflow permissions; full-SHA action pins; exact OIDC audience and subject; environment approval; dedicated deploy role; permission boundary/SCP; artifact attestation with expected signer workflow/source; deployment target authorization.

**Detection evidence**

Unexpected workflow dispatch/ref, OIDC token issuance context, `AssumeRoleWithWebIdentity` principal/session, novel source/workflow, role use outside expected deployment API, artifact digest change, failed/overridden admission.

**Test that should fail**

Run an authorized fixture from the wrong repository, branch, environment and audience. Each must fail role assumption. A valid role session attempting an out-of-scope resource/action must also fail.

**What's still not solved**

Compromised approved maintainer, protected workflow, identity provider, runner or cloud control plane; validly signed malicious source; review collusion; overly broad emergency role; telemetry delay.

**Control classification:** workflow permissions, trust conditions, IAM and admission are preventive; OIDC/STS/deployment telemetry is detective; artifact rollback, role disablement and environment recovery are recovery controls.

## Scenario 2: compromised Kubernetes workload → workload identity → cloud data plane

**Initial foothold**

Attacker executes code in the specific application container. This does not imply node, cluster-admin, or another pod's identity.

**Required preconditions**

The pod can obtain or use a projected service-account/workload token; the token has the expected issuer/audience/subject; cloud federation trusts that exact identity; network/DNS can reach the token and data endpoints; cloud policy permits a consequential data action; and no tenant/object guardrail denies it.

**Edge-by-edge path**

1. **Code execution → workload credential:** projected token, metadata/identity socket or SDK credential path is available to the compromised process. Enforcement: pod spec, token automount, file permissions and workload identity agent.
2. **Credential → cloud session:** federation validates issuer, audience, subject/service account and configured trust. Enforcement: cloud trust/federated-credential object.
3. **Session → service endpoint:** DNS, route, endpoint and security controls permit connection. Enforcement: CNI/node egress, VPC routes, endpoints and security rules.
4. **Cloud API → data operation:** identity/resource/endpoint/SCP policy and service-specific conditions permit the exact resource action. Enforcement: cloud IAM and data-plane resource policy.

**Evidence source**

Pod/deployment and resolved image digest; service account UID; projected-token configuration and decoded non-secret claims; workload-federation trust; CNI/VPC path; effective cloud policies; CloudTrail/data-access logs; runtime process/network telemetry.

**Preventive controls**

No token automount where unnecessary; one bounded service account per trust class; exact audience/subject trust; least-privilege cloud role; resource/endpoint policy; CNI/node egress control; read-only/non-root/seccomp/capability controls; separate node/cluster boundary for hostile tenants.

**Detection evidence**

Unexpected token exchange, cloud session name/tags, API calls outside workload baseline, access from new pod/node, denied endpoint/resource-policy calls, unusual process lineage, data-volume anomaly.

**Test that should fail**

Wrong namespace/service account/audience must fail federation; pod without the identity must not receive credentials; valid session must be denied another bucket/table/key/tenant; blocked egress path must prevent endpoint access.

**What's still not solved**

Compromised authorized workload can exercise its legitimate permissions; in-memory token theft within validity; node/identity-agent compromise; mis-scoped wildcard policy; side channels; missing data events; provider or policy-evaluation defects.

**Control classification:** pod identity, federation trust, egress and cloud policy are preventive; audit/runtime/data-access telemetry is detective; token/role disablement, workload quarantine and data recovery are recovery controls.

## Scenario 3: cross-tenant application flaw → data-store authorization boundary

**Initial foothold**

Attacker is a valid user or client in tenant A and can control an object identifier, filter, route tenant, job message or cache key. No infrastructure compromise is assumed.

**Required preconditions**

The API accepts the request; application identity is authorized to query the data store; tenant/user context is missing, mutable, stale or inconsistently propagated; query/cache/queue/storage authorization fails to bind the object to tenant A; and the returned data or side effect is observable.

**Edge-by-edge path**

1. **Valid tenant-A identity → API request:** authentication succeeds but supplies attacker-controlled object input. Enforcement: route/request schema and authenticated tenant binding.
2. **API → application authorization:** service fails to decide subject, tenant, object and action, or trusts a mutable header. Enforcement: centralized policy or service-owned object authorization.
3. **Application → data query:** shared database credential can access rows beyond tenant A and the query omits tenant predicate/context. Enforcement: tenant-scoped query/repository and database row-level policy where appropriate.
4. **Data result → response/cache/job:** cross-tenant result is returned, cached under a non-tenant key, or delivered to a queue/object path without tenant binding. Enforcement: response filtering, tenant-scoped cache/queue/storage namespace and downstream authorization.

**Evidence source**

API route/auth policy; data-flow and trust-boundary model; authorization decision log; query/repository code; database role and row-security policy; pool/session-context behavior; cache key; queue envelope; object-storage resource policy; positive/negative tenant fixtures.

**Preventive controls**

Server-derived tenant context; object lookup by tenant plus ID; deny-by-default authorization; forced database row security for the application role where used; transaction-local tenant context; scoped cache/queue/object keys; service-side reauthorization; least-privilege data role.

**Detection evidence**

Cross-tenant authorization denials, mismatched route/token/object tenant, unusual object enumeration, database rows returned across context, cache-key collisions, queue tenant mismatch, support/emergency path use.

**Test that should fail**

Tenant A cannot read/update/delete tenant B's object by ID, alternate route, batch/filter, cache, queue replay or object-storage key. Missing tenant context fails closed. Reused pooled connection does not retain the previous transaction's tenant context.

**What's still not solved**

Policy/query defects shared across all layers, privileged database roles that bypass row policy, table owner/superuser/BYPASSRLS behavior, stale relationship data, support impersonation, backup/analytics copies, cache/queue consumers not covered by the tested API path.

**Control classification:** application/data-store/cache/queue authorization is preventive; decision/query anomaly telemetry is detective; cache invalidation, data correction, credential rotation and tenant incident response are recovery controls.

## Control breaks and prioritization

| Priority signal | Higher confidence/urgency | Lower confidence or unknown |
|----|----|----|
| Starting point | Observed compromised principal/asset with timestamp | Hypothetical “internet attacker” without a reachable interface |
| Edge evidence | Current config plus authorized runtime decision | IaC-only, stale graph or name-based inference |
| Conditions | Exact request context satisfies all known conditions | Conditions discarded during graph ingestion |
| Impact | Specific tested read/write/deploy action | Generic “admin” or “data access” label |
| Control breaks | No independently tested denial before impact | Multiple boundaries, each recently confirmed to actually deny it |

Pick the earliest reliable point in the chain that removes the required capability without unacceptable operational impact. I'd rather delete an unnecessary trust relationship, route, or permission than bolt on another detector. Keep detective and recovery controls around anyway, because preventive configuration drifts or gets bypassed.

## Testing what should get denied

For every graph build, test:

- wrong issuer, audience, subject, branch, repository, namespace, service account and tenant;
- route absent while identity is valid, and identity denied while route is present;
- explicit deny, permission boundary, session policy, SCP and resource-policy effects;
- stale collection after policy/workflow/deployment changes;
- runtime-only state absent from IaC, including resolved digest, token claims, session tags, emergency exception and pooled tenant context;
- valid identity without target action/object authorization; and
- recovery: revoke/disable, quarantine, roll back artifact/configuration, restore data and preserve evidence.

Version the graph schema and collectors. Record collection errors and permissions; a least-privilege collector may legitimately leave unknowns. Alert when a high-impact edge exceeds its maximum age, when a preventive control is removed, and when a case that's supposed to be denied stops actually being denied.

## MITRE ATT&CK mappings

ATT&CK describes observed adversary behaviors; it is not an attack-path proof system. Add a technique only when the scenario actually contains that behavior and cite the current Enterprise or Containers technique page. Do not infer exploitability from the existence of a technique ID, and do not force a cloud/IAM/application authorization edge into a technique that describes something else. This article intentionally leaves scenario-specific technique IDs out until an observed or tested behavior warrants them.

## What's still not solved

A compromised trusted maintainer or identity provider, runtime state the collectors never see, stale or incomplete graphs, bugs in conditional-policy evaluation, ephemeral credentials stolen and used within their validity window, policy exceptions, cloud-provider and application bugs, business operations that are valid but still malicious, telemetry loss, and recovery actions that destroy the evidence or availability you needed — all still real. A graph helps with investigation and prioritization; it never replaces checking each edge yourself.

## References

- [GitHub Actions OpenID Connect security model](https://docs.github.com/en/actions/concepts/security/openid-connect)
- [GitHub OIDC token claims and subject customization](https://docs.github.com/en/actions/reference/security/oidc)
- [AWS IAM policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
- [AWS IAM OIDC identity providers and role trust](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html)
- [AWS STS `AssumeRoleWithWebIdentity`](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html)
- [Kubernetes service-account workload identity](https://kubernetes.io/docs/concepts/security/service-accounts/)
- [Kubernetes NetworkPolicy reachability](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [PostgreSQL row security, owner and BYPASSRLS behavior](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [MITRE ATT&CK Enterprise techniques](https://attack.mitre.org/techniques/enterprise/)
- [Repository IAM/OIDC policy-model lab](../labs/iam-oidc/README.md)
- [Repository Kubernetes policy-model lab](../labs/kubernetes-security/README.md)
- [Repository PostgreSQL tenant-boundary lab](../labs/postgresql-rls/README.md)
