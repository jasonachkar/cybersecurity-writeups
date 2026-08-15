---
title: "Software Supply-chain Evidence: SBOMs, Provenance, Signing, and Verification"
id: "supply-chain-sbom-signing"
navTitle: "Supply-chain evidence"
order: 30
type: "devsecops"
tags:
  - devsecops
  - supply
  - chain
  - sbom
  - signing
date: "2026-07-25"
lastReviewed: "2026-07-25"
reviewStatus: "partially-verified"
validatedAgainst:
  - "SLSA v1.2 build provenance — https://slsa.dev/spec/v1.2/build-provenance"
  - "SLSA v1.2 artifact verification — https://slsa.dev/spec/v1.2/verifying-artifacts"
  - "CycloneDX specification overview — https://cyclonedx.org/specification/overview/"
  - "SPDX specifications — https://spdx.dev/use/specifications/"
  - "Sigstore Cosign verification — https://docs.sigstore.dev/cosign/verifying/verify/"
  - "GitHub artifact attestations — https://docs.github.com/en/actions/concepts/security/artifact-attestations"
sourceQuality: "primary-sources-reviewed"
implementationStatus: "partially-tested"
reviewIntervalDays: 90
---

# Software Supply-chain Evidence: SBOMs, Provenance, Signing, and Verification

SLSA v1.2 is the reviewed approved version and defines separate tracks with track-specific levels; it is not one universal maturity score for every workflow.

An SBOM lists components. Provenance describes how an artifact was built. A signature or transparency entry authenticates a statement under a particular identity model. None of those facts alone establish that software is safe or authorized for a target environment. The security control is a verifier that binds all evidence to the exact artifact digest and enforces an explicit identity, source, build, and environment policy.

The [`labs/supply-chain`](../labs/supply-chain/README.md) lab reproduces artifact- digest, builder-ID, build-type, source, issuer, external-verification-result, tamper, and SBOM-format checks offline.

## The core decision

Build once on a protected, isolated builder. Address the output by cryptographic digest. Generate a current-format SBOM and SLSA provenance predicate, obtain an attestation through an approved identity/signing service, and store evidence with the artifact. Before promotion:

1. verify the signed attestation envelope, signer/key or certificate chain, expected issuer/identity, and required transparency evidence;
2. bind that successful verifier result to the exact provenance statement;
3. calculate the artifact digest and match exactly one statement subject;
4. independently enforce `runDetails.builder.id`, `buildDefinition.buildType`, canonical source, and all recognized external parameters; and
5. apply the target environment's evidence, waiver, and approval policy.

Use SLSA v1.2 for new mappings, CycloneDX 1.7 or SPDX 3.0 for new examples depending on ecosystem needs, and record older format versions where interoperability requires them. Treat GitHub's SLSA-level statements as platform-specific claims with their documented conditions; do not generalize them to unrelated build systems.

## Scope and non-goals

In scope:

- build provenance, SBOM lifecycle, keyless/key-based signing, verification policy, artifact promotion, confirming rejected inputs are actually rejected, operations, and incident response;
- OCI/container and file artifacts at an architectural level;
- SLSA v1.2 concepts and current SBOM specification status;
- the separation between signed statement, external verifier result, and authorization policy.

Not established:

- absence of malicious source, vulnerable dependencies, compiler compromise, or exploitable configuration;
- truth of arbitrary claims merely because a signature validates;
- a complete organization PKI/HSM design;
- legal license conclusions from an automated SBOM/license scanner;
- one universal SLSA level for every workflow;
- production cryptographic verification by the offline fixture harness.

## Threat model

```
flowchart LR
  S["Reviewed source and locked inputs"] --> B["Trusted builder platform"]
  B --> A["Artifact digest"]
  B --> V["SLSA provenance statement"]
  B --> M["SBOM"]
  V --> E["Signed attestation envelope"]
  E --> X["External cryptographic verifier result"]
  A --> P["Promotion policy evaluator"]
  V --> P
  M --> P
  X --> P
  Y["Environment policy and valid waiver"] --> P
  P --> D["Deploy exact digest"]
  T["Attacker: source, dependency, runner, registry, signer, verifier"] -. "tamper or substitute" .-> P
```

| Abuse case | Required verifier/control response |
|----|----|
| Artifact bytes changed after build | Calculated digest no longer matches provenance subject; block |
| Valid attestation from an untrusted signer, builder, repository, or workflow | Signer-builder/source/build policy mismatch; block |
| Trusted builder ID paired with an unexpected build type | Validate both fields independently; block either mismatch |
| Attacker swaps provenance predicate type | Exact statement/predicate allowlist; block |
| Signature service unavailable | Explicit failure/risk-acceptance path; never interpret missing evidence as pass |
| “Verified” result is replayed for modified provenance | Require the authenticated statement returned by the verifier to match the policy-evaluated statement; block mismatch |
| SBOM belongs to another image | Bind SBOM attestation to the same subject digest; block mismatch |
| Mutable tag is retargeted | Resolve and deploy digest; tags are discovery labels only |
| Build uses unrecorded input | Verify external parameters/dependencies; lower assurance if completeness is unknown |
| Keyless identity subject is broader than intended | Match expected issuer and narrow certificate/workflow identity |
| Signing key or trusted builder is compromised | Revoke trust, inventory affected evidence, quarantine and rebuild |
| Vulnerable component is absent from SBOM | Validate generation coverage and compare multiple inventory/runtime signals |

## Architecture decision record

### Selected evidence chain

1. Protected source revision and locked inputs.
2. Ephemeral or isolated build environment with a narrow workload identity.
3. Immutable artifact digest in a controlled registry.
4. CycloneDX or SPDX SBOM bound to that digest.
5. SLSA provenance describing source, build definition/type, builder identity, and available inputs without embedding an envelope-verification result.
6. Separately verified signing/attestation identity and, where applicable, transparency evidence.
7. Independent promotion policy evaluator with environment and waiver validation.
8. Deployment and runtime inventory recording the exact digest.

### Keyless versus managed keys

Keyless signing, such as Sigstore's OIDC-based flow, reduces long-lived signing-key custody and can make workload identity visible in certificates and transparency evidence. It shifts trust to OIDC, certificate authority, transparency, workflow protection, clock/network behavior, and precise identity matching.

Managed signing keys can support offline/private environments and existing PKI/HSM controls, but require generation, access, rotation, backup, revocation, audit, and disaster-recovery procedures. Do not store a private signing key as an ordinary CI secret. Select per threat model and record the trust roots.

### Why an SBOM is not a gate by itself

An SBOM may be incomplete, stale, mislabeled, or detached from deployed bytes. It is useful for component inventory, vulnerability response, policy, licensing review, and customer evidence only when generation coverage and artifact binding are understood. A zero-vulnerability scan reflects one database, tool, configuration, and time - not proof of safety.

## SLSA v1.2 field semantics

SLSA v1.2 provenance models a particular build invocation. A level communicates properties of that build path and its evidence, not a quality grade for the source.

### Builder identity is not build type

The two fields have separate security meanings:

- `predicate.buildDefinition.buildType` identifies the parameterized template or process used for the build and defines how its parameters are interpreted.
- `predicate.runDetails.builder.id` identifies the trusted build platform that ran the invocation - the transitive trust base expected to record accurate provenance.

A workflow URI placed in `buildType` and compared with a policy field called `builderId` validates neither property correctly. Consumers must constrain both fields. A trusted platform could otherwise run an unintended template, or an allowed template could be reported by an untrusted platform.

### Builder identity is also distinct from signer identity

The signer/key or certificate identity and issuer authenticate the attestation envelope. They do not replace `builder.id`. SLSA verification guidance recommends a root of trust that accepts authorized signer-builder pairs, followed by checks of `buildType`, source, and external parameters.

This separation supports signers that issue attestations for multiple builders and builders that operate in modes with different security properties. Each materially different trust base should have a distinct builder ID and an appropriately narrow signer policy.

### Cryptographic verification is external to the statement

A conforming SLSA v1 statement keeps `buildDefinition` and `runDetails` inside its predicate. DSSE/signature, certificate/key, signer-identity, and transparency checks are performed on the attestation envelope before statement policy is applied.

Adding a custom top-level object such as:

```json
{
 "verification": {
 "issuer": "<issuer>",
 "verified": true
 }
}
```

cannot establish cryptographic validity. An attacker able to edit the statement could edit that object too. Keep the external verifier result in a separate trusted process boundary, bind it to the exact verified statement, and never let the build under test forge the result consumed by promotion policy.

### Source and external parameters

After envelope verification, compare the canonical source, `buildType`, and every recognized `externalParameters` field with expectations. Reject unexpected external parameters unless the selected build-type policy explicitly defines them as safe. This prevents an authorized builder from running an attacker-selected source, configuration, entry point, or parameter set.

Record at minimum:

- SLSA specification version and track;
- statement and provenance predicate version;
- builder ID and build type as separate values;
- source repository, commit/ref, external parameters, and resolved dependencies;
- artifact subject name and digest;
- authenticated signer/issuer identity and trust root;
- verifier policy/version/result and known gaps;
- isolation and tamper-resistance controls actually satisfied.

GitHub documents that its artifact attestations by themselves can provide SLSA Build Level 2 provenance and that a qualifying reusable build workflow can support its documented Level 3 pattern. Those are conditional GitHub-specific claims. Verify the actual workflow and current documentation rather than labeling all Actions builds L3.

## SBOM format and lifecycle

CycloneDX 1.7 and SPDX 3.0 are current when reviewed. Choose based on consumer/tool interoperability and required data model. Each SBOM should record format/spec version, serial/document identity, generator and version, timestamp, primary component/artifact, component identifiers/hashes where available, relationships/dependencies, and known scope exclusions.

Operational lifecycle:

1. generate during the trusted build from resolved dependencies and output;
2. validate schema and organization-required fields;
3. bind or attest it to the artifact digest;
4. retain it with provenance, scans, and deployment record;
5. continuously re-evaluate deployed inventories as intelligence changes;
6. supersede, never silently edit, historical evidence.

## Verification policy

Verification is authorization. A production policy normally requires:

- locally calculated artifact digest equals exactly one attested subject;
- external verifier authenticated the envelope, signer/key or certificate chain, expected issuer/identity, and required transparency evidence;
- verifier result is bound to the exact statement payload;
- accepted statement type, predicate type, and schema version;
- trusted `runDetails.builder.id` paired with the authenticated signer identity;
- allowed `buildDefinition.buildType` and required/recognized external parameters;
- allowed canonical source repository, ref/tag policy, and commit relationship;
- exact or tightly matched workflow/service identity;
- SBOM format/version and artifact binding;
- required scanner reports tied to digest and tool/configuration version;
- valid time-bounded waiver/approval for the target environment;
- deployment by digest with runtime digest recorded.

Avoid identity regexes that unintentionally accept forks, renamed repositories, unprotected branches, or arbitrary workflows. Test policy with authorized and near-miss signer, builder, build-type, source, parameter, and digest values. Separate builder/signing identity from promotion/deployment identity so one compromised job cannot create and approve its own evidence.

## Admission and runtime enforcement

Cluster admission can require digest references and verified attestations through a policy controller. Fail-open versus fail-closed behavior during registry, identity, transparency, or verifier outages must be a conscious environment decision. Production typically needs a controlled emergency path rather than silent fail-open.

Admission evidence is not runtime continuity. Record the running image digest, watch for mutable-tag drift, unauthorized debug containers, node-local image substitution, and workloads created through exempt identities or namespaces. Protect policy controller, webhook configuration, trust roots, and exemptions as privileged assets.

## Failure modes

- **Attestation missing or invalid:** block promotion; rebuild through trusted path.
- **Verification service unavailable:** pause, or use a documented time-bounded emergency procedure with cached trust material and equivalent audit.
- **Verifier result not bound to statement:** block; never accept a detached boolean.
- **Builder ID or build type mismatch:** block even if signature is valid.
- **Unexpected external parameter:** block until policy explicitly recognizes it.
- **Transparency service unavailable:** apply documented offline/bundle policy; do not confuse inability to look up evidence with successful validation.
- **SBOM generation failure:** block required-evidence policy; never emit empty success.
- **Registry tag changed:** deploy and compare digest; investigate retargeting.
- **Signer or builder compromise:** revoke trust, enumerate issued evidence, quarantine affected digests, rebuild, and update verifiers.
- **Vulnerability discovered later:** query deployed digest/SBOM inventory, assess reachability/exposure, remediate, and preserve original evidence.
- **Policy rollout rejects valid workloads:** canary/report first, version policy and exemptions, and roll back policy version - not verification globally.

## Deployment and rollback

Adopt incrementally:

1. inventory registries, builders, build types, package managers, release identities, and deployed artifact references;
2. enforce immutable digests and protected build source;
3. generate and retain schema-valid SBOM/provenance in observation mode;
4. integrate a real envelope verifier with narrow signer and issuer policy;
5. deploy an independent policy evaluator with negative signer, builder, build-type, source, parameter, statement-binding, and digest tests;
6. canary enforcement in a non-production environment;
7. create narrow, owned, expiring exemptions;
8. enforce by environment and rehearse issuer/registry/verifier outage response.

Rollback deploys a previously verified digest whose evidence remains acceptable under current policy. If current policy rejects the old artifact, rollback requires explicit risk acceptance or a rebuilt artifact - not retagging or bypassing verification.

## Validation evidence

Run:

```powershell
npm ci --ignore-scripts
node labs/supply-chain/tests/run-tests.js
```

The lab validates exact artifact hash, statement/predicate types, and independent `expectedBuilderId`, `expectedBuildType`, `expectedSourceUri`, and `expectedIssuer` policy fields. Tests confirming these get rejected cover:

- wrong builder ID;
- wrong build type;
- missing `runDetails`;
- wrong source;
- wrong issuer;
- failed external cryptographic-verification result;
- verifier-result/statement mismatch;
- incorrect provenance subject digest;
- modified artifact bytes; and
- the CycloneDX 1.7 format field.

The SLSA fixture contains `predicate.runDetails.builder.id` and no custom `verification` object. Cryptographic status, issuer, and the authenticated statement returned by the external verifier are held in `verifier-result.valid.json`; negative tests create separate temporary results. The harness requires that authenticated statement to deep-match the policy-evaluated provenance so the result cannot be replayed for a modified statement.

The lab deliberately does not implement signature cryptography. Its verifier-result format is a tested pedagogical adapter contract representing trusted output from an external verifier. Production Cosign and GitHub attestation commands are documented in the lab but not claimed as executed because they require published artifacts and platform identity.

## Observability and operations

Retain and search:

- source commit/ref, build run, builder ID, build type, and external parameters;
- artifact digest and registry coordinates;
- provenance/SBOM/signed bundle plus statement-bound verifier result;
- signer/key or certificate identity, issuer, trust root, transparency state;
- verification and environment policy versions and decision reasons;
- dependency lockfiles and scanner/tool/database/configuration versions;
- approval/waiver owner, scope, expiry, and ticket;
- deployment environment, runtime digest, actor, and time;
- trust-root, signer, issuer, builder, build-type, source, and exemption changes.

Alert on unattested promotion, signer-builder mismatch, build-type/source/parameter mismatch, detached verifier result, tag/digest changes, expired waivers, verifier fail-open state, new trust roots/builders, unusual signing volume, missing SBOM coverage, and runtime digest absent from approved inventory.

## The cost, and what's still not solved

Generating all this evidence costs build time, storage, registry operations, policy maintenance, and time spent analyzing incidents. Strict identity and digest policy makes experimentation and emergency rollback harder. Give people fast feedback, a way to test policy locally, exemptions someone actually owns, and reliable verification infrastructure, or they'll route around it.

What's still not solved: malicious code from an otherwise-authorized source, a compromised trusted signer or builder, bugs in the verifier itself, incomplete provenance or SBOMs, dependency confusion, runtime mutation, external parameters I haven't modeled, and identities that are broader than they should be. Strong evidence shortens how long detection and response take; it doesn't make those risks disappear.

## Limitations

The offline lab is an educational policy harness. It is not an in-toto envelope, DSSE/signature implementation, Sigstore certificate-chain/transparency verifier, GitHub attestation bundle parser, or Kubernetes admission controller. Its separate verifier-result fixture is not a vendor interchange format and must be produced by a trusted adapter in production. Integrations must use supported tools/libraries and test current platform-specific semantics, including signer-builder pairing and all recognized external parameters.

## References

- [SLSA v1.2 build provenance](https://slsa.dev/spec/v1.2/build-provenance)
- [SLSA v1.2 artifact verification](https://slsa.dev/spec/v1.2/verifying-artifacts)
- [CycloneDX specification overview](https://cyclonedx.org/specification/overview/)
- [SPDX specifications](https://spdx.dev/use/specifications/)
- [Sigstore Cosign verification](https://docs.sigstore.dev/cosign/verifying/verify/)
- [GitHub artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations)
- [GitHub secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
