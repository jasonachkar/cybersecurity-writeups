---
title: "Secrets Management Engineering: Identity, Delivery, Rotation and Runtime Exposure"
type: "devsecops"
tags:
  - devsecops
  - secrets
  - management
date: "2026-07-25"
lastReviewed: "2026-07-25"
readingTime: 9
reviewStatus: "partially-verified"
validatedAgainst:
  - "Kubernetes Secrets — https://kubernetes.io/docs/concepts/configuration/secret/"
  - "Kubernetes Secret volumes and tmpfs behavior — https://kubernetes.io/docs/concepts/storage/volumes/#secret"
  - "Kubernetes `emptyDir` and `medium: Memory` — https://kubernetes.io/docs/concepts/storage/volumes/#emptydir"
  - "Kubernetes Linux-node protection for memory-backed secret data — https://kubernetes.io/docs/concepts/security/linux-security/#protection-for-secret-data-on-nodes"
  - "Secrets Store CSI Driver architecture and security boundary — https://secrets-store-csi-driver.sigs.k8s.io/concepts.html"
  - "HashiCorp Vault lease, renewal and revocation — https://developer.hashicorp.com/vault/docs/concepts/lease"
sourceQuality: "primary-sources-reviewed"
implementationStatus: "illustrative"
reviewIntervalDays: 90
---

# Secrets Management Engineering: Identity, Delivery, Rotation and Runtime Exposure

A secrets manager is a control plane, not a guarantee of least privilege. The security boundary is the complete path from workload identity through authorization and delivery to runtime use, rotation, revocation, audit, and recovery.

## The core decision

Prefer workload identity and short-lived, audience-bound access where the target supports it. When a third-party system still requires a long-lived reusable credential, treat it as a governed exception: narrow its permissions and allowed source, protect storage and delivery, rotate on a tested schedule, monitor use, and maintain an emergency revocation path.

Short lifetime reduces replay duration; it does not repair excessive privilege. Dynamic credentials reduce sharing and improve attribution; they can still be stolen, overprivileged, orphaned, or left active when revocation fails.

## Scope, assets and threats

Assets include secret-manager root/control credentials, workload identities, policies, secret values and versions, encryption keys, lease metadata, database plugin root credentials, mounted files, environment variables, process memory, audit logs, backups, and emergency access.

| Threat | Required precondition | Primary control |
|----|----|----|
| Unauthorized retrieval | Over-broad identity/policy or compromised authorized workload | Bound workload identity, least-privilege path/resource policy, tenant separation |
| Delivery interception | Compromised node, sidecar, agent, transport or writable mount | Authenticated channel, read-only mount, node hardening, narrow delivery component |
| Runtime disclosure | Process inspection, debug/exec, child process, logs, crash dump or code compromise | Minimize value lifetime/copies, restrict debug access, redact and isolate |
| Stale credential | Cache/connection survives rotation or consumer misses refresh | Version-aware refresh, overlap/retry strategy, observable cutover |
| Failed revocation | Plugin/target/control-plane failure | Reconciliation, target-side inventory, emergency native revocation |

## Identity and delivery patterns

| Pattern | Who retrieves/writes | Authorization identity | Trade-offs |
|----|----|----|----|
| Application retrieval | Application client calls external manager | Workload identity bound to exact secret path | Clear ownership; application handles cache, outage, rotation and memory |
| Kubernetes Secret volume | Kubelet projects an authorized Secret object into the pod | Control-plane/node authorization plus pod reference | Simple and read-only; Secret exists in Kubernetes API and node boundary |
| Secrets Store CSI Driver | Privileged node driver calls a provider and mounts returned content | Provider-specific pod/workload identity and `SecretProviderClass` | External source; privileged driver/provider and forwarded identity expand node trust |
| Reviewed sidecar/init agent | Agent authenticates, writes/renews file or shared memory-backed volume | Agent/workload identity and manager policy | Separates client logic but introduces shared process/volume, lifecycle and agent trust |

An `emptyDir` with `medium: Memory` only creates a writable memory-backed volume. It does not retrieve, authorize, or inject a secret. A separate component must write the value, and every container that can mount/read that volume joins the exposure boundary.

## Kubernetes Secret semantics and exposure

Ordinary `kubectl get` and `kubectl describe` output does not normally print Secret values. An authorized principal can explicitly retrieve the Secret's base64-encoded `data`, which is encoding, not encryption. Risk therefore centers on real permissions and runtime access, not a universal claim that describing a pod reveals values.

**Illustrative Kubernetes Secret-volume pattern; YAML syntax only, no cluster test:**

``` yaml
apiVersion: v1
kind: Pod
metadata:
  name: payments-api
spec:
  serviceAccountName: payments-api
  containers:
    - name: app
      image: registry.example.invalid/payments@sha256:<digest>
      volumeMounts:
        - name: database-credential
          mountPath: /run/secrets/database
          readOnly: true
  volumes:
    - name: database-credential
      secret:
        secretName: <database-secret-name>
        defaultMode: 0400
```

Here the kubelet projects an existing Kubernetes Secret into a read-only Secret volume. This example does not show creation, encryption at rest, authorization policy, rotation, image verification, node hardening, or application reload behavior. On Linux, Kubernetes documents Secret volumes as tmpfs-backed, subject to node/kernel swap considerations; tmpfs does not protect against root, kubelet, node, privileged pod, or process compromise.

Relevant exposure paths include:

- principals authorized to read Secret objects or impersonate such principals;
- `exec`, ephemeral-container/debug, process-memory or filesystem access;
- application diagnostics, logs, traces, crash dumps and error responses;
- child processes and inherited descriptors/environment;
- compromised workloads, overly broad/shared mounts, sidecars and init containers;
- node, kubelet, privileged daemonset, service-account or control-plane compromise; and
- backups, etcd access, GitOps/rendered manifests and CI artifacts.

## Environment variables and memory exposure

Environment variables can be acceptable under some threat models, but they can flow to child processes and may be exposed through process-environment inspection under applicable OS/container permissions, diagnostics, crash reports, support bundles, application logs, template rendering, or compromised code. Do not imply that an arbitrary host user can always read `/proc/1/environ`; Linux permissions, namespaces, ptrace settings, container policy and runtime matter.

Files on a memory-backed volume avoid ordinary persistent-volume writes but remain plaintext to authorized readers and privileged node actors. Application retrieval avoids a shared file but places plaintext in the process. Secret zeroization is not reliable in garbage-collected languages because copies, immutable strings, compiler/runtime behavior, crash dumps and allocator reuse may persist beyond the application's intent.

Minimize secret size, scope, copies and lifetime; avoid string formatting; restrict debug/dump capability; use dedicated processes or hardware-backed operations when the threat model requires stronger key isolation; and test actual exposure rather than asserting “memory-only” safety.

## Vault dynamic credentials and workload binding

Vault dynamic secrets have leases. A consumer receives a lease ID, duration and renewability information; renewal requests are advisory and the resulting TTL must be inspected. Expiry means the consumer can no longer assume the credential remains valid while Vault attempts the backend-specific revocation.

A production design must cover:

- **Identity binding:** for Kubernetes auth, bind service-account names/namespaces and audience; prefer UID-based aliases when compatible.
- **Policy:** authorize only the required database role/secret path and capabilities; avoid default broad policies.
- **Database plugin:** protect and rotate the plugin's root/admin credential; restrict network access and database grants used to create users.
- **Lease lifecycle:** issue, renew before expiry, reacquire after failed renewal, revoke on shutdown where useful, and reconcile target users.
- **Audit devices:** enable and monitor at least one appropriate audit destination, protect it from the Vault operator path as required, and alert on audit failure.
- **Tenant separation:** separate mounts, policies, auth roles and administrative ownership; use Vault Enterprise namespaces only when licensed/required and understand parent administration.
- **Emergency access:** protect unseal/recovery and root-generation material, use multi-person procedures, log use, and revoke generated root tokens immediately after the emergency.

Orphan tokens have no parent and therefore do not inherit parent-token revocation behavior. Use them only with a deliberate lifecycle and monitoring model.

## Rotation and revocation semantics

Rotation has at least four states: create pending credential, make it valid at the target, move consumers, and retire the old credential. Define overlap, cache TTL, connection-pool behavior, retry, rollback and the evidence that every consumer moved.

Do not guarantee that every expired lease instantaneously removes a database user. Revocation depends on Vault availability, the expiration manager, plugin health, network reachability, valid administrative credentials, and the target database. A failed revoke can leave an orphaned user or credential. Reconcile Vault leases against native database/cloud identity inventory and alert on users past their intended lease.

Native target revocation is the fallback when the manager or plugin cannot act. Document who can invoke it, how to preserve evidence, how to avoid deleting shared identities, and how applications recover.

## Failure modes

| Failure | Security/availability effect | Required behavior |
|----|----|----|
| Secret manager unavailable | New retrieval/renewal fails | Bounded cache policy, fail closed for privileged actions, no hard-coded fallback |
| Identity provider unavailable | Workloads cannot authenticate or renew | Existing-token TTL policy, alerting and recovery without a shared emergency token |
| Rotation partially completes | Old/new values disagree across store, target and clients | Idempotent stages, version labels, target verification and rollback |
| Database revoke fails | Expired lease may leave active user | Queue/retry, target inventory reconciliation and native emergency revoke |
| CSI/agent fails or is compromised | Pod startup outage, stale data or node-wide exposure | Health monitoring, pinned/supported versions, node isolation and tested fallback |
| Audit destination unavailable | Loss of accountability or service refusal depending on product behavior | Independent health, protected capacity and documented fail behavior |
| Root/control credential exposed | Manager-wide compromise | Rotate/revoke, seal/recover where applicable, audit and downstream credential response |

## Cases that should fail

**This is the test plan I'd run against a real Vault/Kubernetes setup — I haven't executed it for this write-up.**

| Case | Expected result |
|----|----|
| Wrong service account, namespace or token audience | Vault/provider authentication denied |
| Authorized identity requests another secret path/tenant | Policy denial |
| Principal can describe pod but cannot read Secret | No Secret value disclosed by ordinary describe output |
| Debug/exec principal attempts mounted-file or process access | Denied by RBAC/admission/runtime policy according to design |
| Application logs/throws secret-bearing value | Redaction/test fails build; no value reaches log sink |
| Rotation during warm cache/pooled connection | Old connection behavior and refresh match documented overlap |
| Renewal rejected or response TTL shortened | Client inspects result and reacquires before loss of service |
| Plugin cannot reach database during revoke | Failure alert plus retry/reconciliation; native user remains visible |
| Orphaned target user | Reconciliation detects and safely revokes it |
| Manager and identity service outage | Bounded degradation; no broad static fallback |

## Observability, rollout and rollback

Log workload identity, auth method, policy/role, requested path (not value), lease ID/accessor where safe, version/stage, issue/renew/revoke result, TTL, target role, cache hit/age, reload result and request correlation. Protect audit data because path names and metadata can still be sensitive. Alert on root/emergency operations, policy/auth changes, broad list/read, repeated denies, renewal failure, expired-but-active target users and audit-device failure.

1. Inventory every secret, owner, consumer, source, delivery path, permission, rotation method and emergency revocation.
2. Migrate one low-risk consumer; test initial retrieval, restart, renewal, rotation, manager outage and rollback.
3. Canary rotation with dual/overlap credentials where the target supports it; verify every consumer before retirement.
4. Restrict debug/exec and node access after confirming operational alternatives.
5. Exercise native target revocation and break-glass under dual control.

Rollback should select a known valid secret version and restore the corresponding target credential/policy. Do not copy a secret into source control, broaden a shared role, disable audit, or distribute a permanent emergency token to recover availability.

## What's still not solved

A compromised authorized workload, a compromised secret manager or identity control plane, privileged node/debug access, plaintext sitting in process memory, stale caches and sessions, target systems that don't support modern federation or rotation, revocation that silently fails, backups and crash dumps, operator abuse, cross-tenant policy mistakes, and incomplete audit trails — none of that is solved by this design. Good secret management cuts down uncontrolled distribution; it doesn't make a compromised consumer safe.

## References

- [Kubernetes Secrets](https://kubernetes.io/docs/concepts/configuration/secret/)
- [Kubernetes Secret volumes and tmpfs behavior](https://kubernetes.io/docs/concepts/storage/volumes/#secret)
- [Kubernetes `emptyDir` and `medium: Memory`](https://kubernetes.io/docs/concepts/storage/volumes/#emptydir)
- [Kubernetes Linux-node protection for memory-backed secret data](https://kubernetes.io/docs/concepts/security/linux-security/#protection-for-secret-data-on-nodes)
- [Secrets Store CSI Driver architecture and security boundary](https://secrets-store-csi-driver.sigs.k8s.io/concepts.html)
- [HashiCorp Vault lease, renewal and revocation](https://developer.hashicorp.com/vault/docs/concepts/lease)
- [HashiCorp Vault token hierarchy and orphan tokens](https://developer.hashicorp.com/vault/docs/concepts/tokens)
- [HashiCorp Vault Kubernetes auth role binding](https://developer.hashicorp.com/vault/api-docs/auth/kubernetes)
- [HashiCorp Vault audit devices](https://developer.hashicorp.com/vault/docs/audit)
- [HashiCorp Vault database secrets engine](https://developer.hashicorp.com/vault/docs/secrets/databases)
