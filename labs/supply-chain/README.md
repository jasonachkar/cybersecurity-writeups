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

<div class="language-powershell highlight">

<span id="__span-0-1"><span class="n">`node`</span>` `<span class="n">`labs`</span><span class="p">`/`</span><span class="n">`supply-chain`</span><span class="p">`/`</span><span class="n">`tests`</span><span class="p">`/`</span><span class="n">`run-tests`</span><span class="p">`.`</span><span class="n">`js`</span>` `</span>

</div>

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

<div class="language-sh highlight">

<span id="__span-1-1">`cosign`<span class="w">` `</span>`verify-attestation`<span class="w">` `</span><span class="se">`\`</span>` `</span><span id="__span-1-2"><span class="w">` `</span>`--type`<span class="w">` `</span>`slsaprovenance`<span class="w">` `</span><span class="se">`\`</span>` `</span><span id="__span-1-3"><span class="w">` `</span>`--certificate-oidc-issuer`<span class="o">`=`</span>`https://token.actions.githubusercontent.com`<span class="w">` `</span><span class="se">`\`</span>` `</span><span id="__span-1-4"><span class="w">` `</span>`--certificate-identity-regexp`<span class="o">`=`</span><span class="s1">`'^https://github.com/jasonachkar/cybersecurity-writeups/'`</span><span class="w">` `</span><span class="se">`\`</span>` `</span><span id="__span-1-5"><span class="w">` `</span>`<artifact-reference> `</span><span id="__span-1-6">` `</span><span id="__span-1-7">`gh`<span class="w">` `</span>`attestation`<span class="w">` `</span>`verify`<span class="w">` `</span>`<artifact-path>`<span class="w">` `</span><span class="se">`\`</span>` `</span><span id="__span-1-8"><span class="w">` `</span>`--repo`<span class="w">` `</span>`jasonachkar/cybersecurity-writeups `</span>

</div>

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
