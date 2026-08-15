---
id: supply-chain
title: Artifact provenance and SBOM verification lab
navTitle: Supply-chain policy
domain: devsecops
order: 70
summary: Exercises offline artifact digest, provenance identity, source, builder, and SBOM policy decisions.
implementationStatus: partially-tested
related:
  research: [supply-chain-sbom-signing]
sourceFiles:
  - { path: labs/supply-chain/verify-provenance.js, label: Verifier, language: javascript, primary: true }
  - { path: labs/supply-chain/policy.json, label: Policy contract, language: json }
  - { path: labs/supply-chain/tests/run-tests.js, label: Tests, language: javascript }
runCommands: [node labs/supply-chain/tests/run-tests.js]
---

# Artifact provenance and SBOM verification lab

SLSA v1.2 uses tracks and track-specific levels, not one universal maturity score.

This offline lab demonstrates policy checks across four deliberately separate inputs:

1. the artifact bytes;
2. a SLSA v1 provenance statement;
3. the trusted output of an external cryptographic verifier; and
4. organization policy.

The policy independently constrains `predicate.runDetails.builder.id`, `predicate.buildDefinition.buildType`, the canonical source URI, and the attestation issuer. The external verifier result must return the authenticated statement, which must deep-match the separately supplied provenance. The statement subject must then match the locally calculated artifact digest.

## Prerequisites and run command

- Node.js 24.12.0 (compatible Node.js 22+ should also work).
- Repository dependencies installed using `npm ci --ignore-scripts`.

```powershell
node labs/supply-chain/tests/run-tests.js
```

Expected output ends in `PASS`. Cases the policy should reject:

- wrong builder ID;
- wrong build type;
- missing `runDetails`;
- wrong source;
- wrong issuer;
- failed cryptographic-verification result;
- a verifier result bound to another statement;
- a provenance subject with the wrong digest; and
- modified artifact bytes.

## SLSA field model

SLSA v1.2 assigns different meanings to fields that must not be conflated:

- `buildDefinition.buildType` identifies the parameterized build template/process;
- `runDetails.builder.id` identifies the trusted build platform for that invocation;
- `subject[].digest` binds provenance to output bytes; and
- signature, certificate, issuer, and transparency checks happen on the attestation envelope before provenance policy is applied.

`policy.json` therefore uses explicit `expectedBuilderId`, `expectedBuildType`, `expectedSourceUri`, and `expectedIssuer` fields.

## External verifier boundary

`verifier-result.valid.json` is a **tested pedagogical adapter contract**, not a Sigstore, Cosign, or GitHub-defined file format. It represents data returned over a trusted in-process boundary after a real verifier has checked the signed envelope, certificate chain or key, signer identity, and any required transparency evidence. I create separate temporary verifier results to test wrong issuer, failed verification, and statement mismatch. Neither the tracked fixture nor temporary results can establish cryptographic validity merely by containing `"verified": true`.

Production code must invoke and authenticate a supported verifier, consume its result without allowing the build under test to forge or replace it, and then enforce the same statement and policy constraints. The fixture carries the statement returned by the external verifier; the harness requires it to deep-match the policy-evaluated statement, so a successful result cannot be replayed for modified provenance.

Example production commands, not executed by this offline lab:

```sh
cosign verify-attestation \
 --type slsaprovenance \
 --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
 --certificate-identity-regexp='^https://github.com/jasonachkar/cybersecurity-writeups/' \
 <artifact-reference>

gh attestation verify <artifact-path> \
 --repo jasonachkar/cybersecurity-writeups
```

Pin the expected artifact digest and narrow workflow identity; do not treat a valid signature from any identity as authorization.

## Failure modes and limitations

An SBOM is an inventory, not evidence that components are vulnerability-free. Provenance describes a build path, not developer intent or source safety. This lab does not implement DSSE parsing, certificate/key validation, transparency-log checks, certificate revocation semantics, reusable-workflow delegation, private-repository identity, key-compromise response, or the production attestation envelope. Those belong to the selected external verifier and platform integration.

The lab binds source in both the GitHub workflow external parameters and `resolvedDependencies`; it also requires the external workflow repository, path, and ref to reconstruct the authorized builder ID. A production GitHub build-type policy should additionally reject every unexpected or unrecognized external parameter.

## Cleanup

Tests remove their temporary verifier results and tampered artifact. No service or cloud resource is created.

## References

- [SLSA v1.2 build provenance](https://slsa.dev/spec/v1.2/build-provenance)
- [SLSA v1.2 artifact verification](https://slsa.dev/spec/v1.2/verifying-artifacts)
- [Sigstore Cosign verification](https://docs.sigstore.dev/cosign/verifying/verify/)
- [GitHub artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations)
- [CycloneDX specification overview](https://cyclonedx.org/specification/overview/)
- [SPDX specifications](https://spdx.dev/use/specifications/)
