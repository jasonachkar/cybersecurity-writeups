# Kubernetes admission, network, and image-policy lab

**Evidence status:** partially tested lab. Native Kyverno v1.18.2 testing exercised the hardened-pod policy. The image policy is a schema-validated example; signature, certificate, registry, transparency, mutation, and live admission were not tested.

This lab validates a narrow Kubernetes security baseline with positive and negative fixtures. It does not claim that a namespace, admission policy, or NetworkPolicy is a hard hostile-tenant boundary.

## Pinned validation scope

- Kubernetes API shapes reviewed for Kubernetes `1.34`.
- Kyverno CLI `1.18.2`.
- Kyverno `policies.kyverno.io/v1` `ValidatingPolicy` and `ImageValidatingPolicy`, stable in Kyverno 1.18.

Run the dependency-free structural and identity-policy tests:

<div class="language-text highlight">

<span id="__span-0-1">`node labs/kubernetes-security/tests/run-tests.js `</span>

</div>

Run the native Kyverno tests:

<div class="language-text highlight">

<span id="__span-1-1">`kyverno test labs/kubernetes-security --remove-color `</span>

</div>

On 2026-07-23, the official Kyverno v1.18.2 Windows CLI asset (SHA-256 `b5c9d1cb75587a312dc8334537a5773bdedb1a985deae9d89a5251385afb831f`) ran the native hardened-pod suite: `7 tests passed and 0 tests failed`. This native run does not include `verify-release-images.yaml`.

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

The accepted Pod is tested alongside privileged, host-namespace, `hostPath`, capability, missing-resource, and token-automount negative fixtures.

`policies/verify-release-images.yaml` uses the stable Kyverno 1.18 `policies.kyverno.io/v1` `ImageValidatingPolicy`. It constrains repository, keyless issuer, full workflow-and-branch subject, SLSA provenance predicate type, required verification, digest verification, and `failurePolicy: Fail`. Separate `:*` and `@sha256:*` globs make tagged and digest references to the exact repository eligible for evaluation while excluding lookalike repositories.

On 2026-07-23, the manifest conformed to Kyverno v1.18.2's official `ImageValidatingPolicy` CRD v1 schema. The downloaded CRD asset SHA-256 was `3528151f3717c9946ee56d60866f2cf6c29a4b1a7e759c72af60451147b995c2`. The Node harness separately evaluates eleven synthetic, already-resolved evidence claim sets. It returns false for unsigned, wrong repository/workflow/branch/issuer/predicate, missing or malformed provenance, verifier/transparency failure, and digest mismatch.

The twelfth case proves only that a tag such as `:latest` matches the reviewed tag selector. Its admission result is deliberately `null`: the harness does not model registry resolution or Kyverno's `mutateDigest` behavior and therefore makes no accept/deny claim for tag-only input. This is a **schema-validated example; no live enforcement test**. Signature, certificate, registry, transparency-log, mutation, webhook failure, and controller behavior were not executed.

## Network boundary

`fixtures/network-policies.yaml` contains namespace-wide default-deny ingress and egress plus an explicit DNS exception. NetworkPolicy has an effect only when the selected CNI implements it. DNS labels, ports, node-local DNS paths, dual-stack behavior, and required application egress must be verified in each cluster. NetworkPolicy does not control all host-network, node, service-mesh, or cloud-network paths.

## Operational rollout

Use `observe → audit → warn → enforce → measure bypasses`. Track policy evaluation errors, denials, exceptions and expiry, unsigned-image attempts, registry/rekor availability, admission latency, and workloads that require a separate runtime class or cluster. Keep a reviewed break-glass path outside tenant administrator control.

## References

- [Kyverno v1.18.2 release and official CRD/CLI assets](https://github.com/kyverno/kyverno/releases/tag/v1.18.2)
- [Kyverno policy type lifecycle](https://kyverno.io/docs/policy-types/overview/)
- [Kyverno ImageValidatingPolicy](https://kyverno.io/docs/policy-types/image-validating-policy/)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Kubernetes ValidatingAdmissionPolicy](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [Kubernetes NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Kubernetes service-account token projection](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)
