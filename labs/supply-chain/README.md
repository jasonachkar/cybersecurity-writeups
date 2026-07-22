# Artifact provenance and SBOM verification lab

This offline lab demonstrates that a verifier must bind an artifact digest to the
expected statement type, builder workflow, source repository/ref, issuer, and a
successful cryptographic-verification result. It also parses a minimal CycloneDX 1.7
SBOM fixture.

## Prerequisites and run command

- Node.js 24.12.0 (compatible Node.js 22+ should also work).
- Repository dependencies installed using `npm ci --ignore-scripts`.

```powershell
node labs/supply-chain/tests/run-tests.js
```

Expected output ends in `PASS`. Negative tests reject a modified artifact, wrong
digest, untrusted builder, and a statement whose signature-verification result is not
successful.

## What is reproduced

The local verifier and deterministic fixtures are tested. The `verification` object
is deliberately a fixture boundary: this lab does **not** implement cryptography or
claim that editing JSON can establish signature validity. In production, populate
verified claims only from an attestation verifier such as Cosign or GitHub's
attestation tooling, then apply the same policy constraints.

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

Pin the expected artifact digest and narrow workflow identity; do not treat a valid
signature from any identity as authorization.

## Failure modes and limitations

An SBOM is an inventory, not evidence that components are vulnerability-free.
Provenance describes a build path, not developer intent or source safety. This lab
does not test transparency-log availability, certificate revocation semantics,
reusable-workflow delegation, private-repository identity, key compromise, or the
production attestation envelope. Those require the selected verifier and platform.

## Cleanup

Tests remove their temporary tampered artifact. No service or cloud resource is
created.

## References

- [SLSA v1.2 specification](https://slsa.dev/spec/v1.2/)
- [Sigstore Cosign verification](https://docs.sigstore.dev/cosign/verifying/verify/)
- [GitHub artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations)
- [CycloneDX specification overview](https://cyclonedx.org/specification/overview/)
- [SPDX specifications](https://spdx.dev/use/specifications/)
