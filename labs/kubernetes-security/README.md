# Kubernetes admission, network, and image-policy lab

This lab validates a narrow Kubernetes security baseline with positive and negative
fixtures. It does not claim that a namespace, admission policy, or NetworkPolicy is a
hard hostile-tenant boundary.

## Pinned validation scope

- Kubernetes API shapes reviewed for Kubernetes `1.34`.
- Kyverno CLI `1.18.2`.
- Kyverno `policies.kyverno.io/v1` `ValidatingPolicy` and
  `ImageValidatingPolicy`, stable in Kyverno 1.18.

Run the dependency-free structural and identity-policy tests:

```text
node labs/kubernetes-security/tests/run-tests.js
```

Run the native Kyverno tests:

```text
kyverno test labs/kubernetes-security --remove-color
```

The repository CI installs the pinned Kyverno CLI and requires the native test.
Local validation reports a limitation when that executable is unavailable.

## Enforcement demonstrated

`policies/hardened-pods.yaml` denies:

- privileged containers and privilege escalation;
- host PID, IPC, or network namespaces;
- `hostPath` volumes;
- added Linux capabilities or failure to drop `ALL`;
- writable root filesystems;
- missing non-root and seccomp configuration;
- missing CPU/memory requests or limits; and
- service-account token automount unless explicitly disabled.

The accepted Pod is tested alongside privileged, host-namespace, `hostPath`,
capability, missing-resource, and token-automount negative fixtures.

`policies/verify-release-images.yaml` uses the current
`ImageValidatingPolicy` type. It narrows the registry/repository, keyless issuer, full
workflow identity, and SLSA provenance predicate type; requires digest verification;
and sets `failurePolicy: Fail`. The dependency-free identity fixtures demonstrate
rejection for unsigned images, a wrong repository/workflow/branch/issuer, absent or
malformed provenance, a mutable tag without a digest, and digest substitution.

The identity tests validate policy decisions and policy structure. They do **not**
perform Sigstore cryptography or make registry/transparency-log calls. A cluster
rollout must additionally run online verification against organization-owned signed
and unsigned images before enforcement.

## Network boundary

`fixtures/network-policies.yaml` contains namespace-wide default-deny ingress and
egress plus an explicit DNS exception. NetworkPolicy has an effect only when the
selected CNI implements it. DNS labels, ports, node-local DNS paths, dual-stack
behavior, and required application egress must be verified in each cluster.
NetworkPolicy does not control all host-network, node, service-mesh, or cloud-network
paths.

## Operational rollout

Use `observe → audit → warn → enforce → measure bypasses`. Track policy evaluation
errors, denials, exceptions and expiry, unsigned-image attempts, registry/rekor
availability, admission latency, and workloads that require a separate runtime class
or cluster. Keep a reviewed break-glass path outside tenant administrator control.

## References

- [Kyverno policy type lifecycle](https://kyverno.io/docs/policy-types/overview/)
- [Kyverno ImageValidatingPolicy](https://kyverno.io/docs/policy-types/image-validating-policy/)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Kubernetes ValidatingAdmissionPolicy](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [Kubernetes NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Kubernetes service-account token projection](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)
