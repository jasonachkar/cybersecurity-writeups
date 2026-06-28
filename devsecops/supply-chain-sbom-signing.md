---
title: "Software Supply Chain Security: SBOM Generation, Container Signing, and SLSA Compliance"
type: devsecops
tags: [Supply Chain, SBOM, Cosign, Sigstore, SLSA Framework]
date: 2026-06
readingTime: 20
---

# Software Supply Chain Security: SBOM Generation, Container Signing, and SLSA Compliance

## Executive Summary

Software supply chain security has become a critical priority for modern enterprises. Modern applications rely heavily on open-source packages, third-party libraries, and container base images. While this speeds up development, it also introduces significant security risks. Attackers target this trust dependency by compromising upstream repositories, hijacking developer accounts, or injecting malicious code during the build process. A single vulnerability in a popular library can instantly compromise thousands of downstream applications.

At scale, relying on simple build-stage vulnerability scans is insufficient. Organizations must implement a complete supply-chain defense model. This requires generating cryptographically verified Software Bills of Materials (SBOMs), signing container images at build time, and adhering to the Supply-chain Levels for Software Artifacts (SLSA) framework. This whitepaper explains how to build secure build pipelines, sign artifacts using Sigstore and Cosign, verify dependencies, and implement automated security gates.

---

## Threat Model and Attack Surface

The software supply chain attack surface spans code repositories, dependency registries, build server environments, and artifact distribution pipelines.

```
       [ Developer Commits Clean Code ]
                      │
                      ▼
          [ CI / Build Pipeline ] ── (Attacker injects build malware)
                      │
                      ▼
         [ Malicious Artifact Built ]
                      │
       ┌──────────────┴──────────────┐
       ▼ (Verification Bypassed)     ▼ (Strict Signature Verification)
[ Deploy to Production ]      [ Verify Image Signature via Cosign ]
       │                             │
       ▼                             ▼
[ System Compromised ]        [ BLOCK: Missing or Invalid Signature ]
                                     ( Secure )
```

### Threat Vectors and Kill-Chains

1. **Upstream Package Hijacking (Dependency Substitution)**:
   - *Adversary Goal*: Inject malicious code into an enterprise application.
   - *Attack Vector*: An attacker identifies a private package name used by an organization. They upload a malicious package with the same name but a much higher version number (e.g. `v99.0.0`) to a public registry like npm or PyPI. During the build process, the application package manager defaults to pulling the public version instead of the private one. The malicious package executes during installation, stealing environment variables and credentials.
2. **Build Pipeline Compromise (Build System Injection)**:
   - *Adversary Goal*: Inject a backdoor into a production binary.
   - *Attack Vector*: An attacker compromises the build host (as in the SolarWinds incident). They inject a malicious compilation step that monitors build directories and replaces a clean source file with a backdoored version immediately before compilation. Because the source code repository remains clean, standard static scanners do not detect the backdoor.
3. **Registry Poisoning (Unauthorized Image Replacement)**:
   - *Adversary Goal*: Replace a secure production container image with a compromised version.
   - *Attack Vector*: An attacker compromises an organization's container registry credentials. They push a malicious image, tag it as `production-latest`, and overwrite the existing secure container. If the deployment cluster does not verify the image digest and cryptographic signature, it runs the malicious container automatically.

---

## Deep Technical Body

### The SLSA (Supply-chain Levels for Software Artifacts) Framework

SLSA is a security framework designed to protect the integrity of software artifacts. It defines standards for source code tracking, build processes, and provenance generation.

#### Core SLSA Security Pillars:
* **Source Integrity**: Track changes using version control systems (like Git) and require multi-person review for all main branch modifications.
* **Build Integrity**: Run builds on isolated, ephemeral build platforms. Generate secure provenance documents that record the exact source commit, build parameters, and dependencies used.
* **Provenance Verification**: Validate the build provenance at deployment time to verify the artifact was built by a trusted pipeline, not an external entity.

### Container Signing and Verification with Cosign

Cosign (part of the Sigstore project) simplifies signing and verifying container images. It stores signatures directly inside the container registry, eliminating the need to manage external signature stores.

```
[ Build Image ] ──> [ Push to Registry ] ──> [ Cosign Signs Image ] ────┐
                                                                       ▼
                                                          [ Push Signature to Registry ]
                                                                       │
                                                                       ▼
[ Deploy Image ] <── [ Cluster Admission Controller (Kyverno) ] <──────┘
                                  │
                       ( Verifies Signature )
                                  │
                      ┌───────────┴───────────┐
                      ▼                       ▼
               [ Run Container ]       [ Reject Image ]
```

#### Keyless Signing Mechanics
Cosign supports keyless signing, which removes the need for managing and protecting long-lived private keys. Keyless signing uses OpenID Connect (OIDC) tokens, ephemeral keys, and public ledgers:
1. **Request Identity**: The build runner requests an OIDC token from the identity provider (e.g., GitHub Actions OIDC).
2. **Generate Key Pair**: Cosign generates a temporary cryptographic key pair inside the runner.
3. **Verify Identity**: Cosign sends the public key and OIDC token to **Fulcio** (Sigstore's certificate authority). Fulcio verifies the token and returns a short-lived certificate (valid for 10 minutes) binding the public key to the runner's OIDC identity.
4. **Sign Artifact**: Cosign signs the container image using the private key, then destroys the key pair.
5. **Record Transaction**: Cosign records the signature and certificate in **Rekor** (Sigstore's public, tamper-resistant transparency log).
6. **Verify Signature**: During deployment, the verifier validates the signature using the certificate and confirms the transaction is recorded in Rekor's public ledger, proving the image was signed by the authorized runner.

---

## Defensive Architecture

A secure supply chain architecture requires generating verified Software Bills of Materials (SBOMs), signing all build artifacts, and enforcing signature verification at deployment time.

### Architecture Topology: End-to-End Build and Verification Flow

```
[ Git Push ] ────> [ GitHub Runner ]
                          │
                  ( Build & Test Code )
                          │
                          ▼
            [ Generate CycloneDX SBOM ] ──> (Saves SBOM to Registry)
                          │
                          ▼
             [ Build Container Image ]
                          │
                          ▼
             [ Cosign Keyless Signing ]
                          │
                          ▼
            [ Push Image to Registry ]
                          │
                          ▼
     [ Kubernetes Cluster (Kyverno Verify) ]
                          │
               ┌──────────┴──────────┐
               ▼ (Valid Signature)   ▼ (No Signature)
         [ Run Workload ]      [ Block Deployment ]
```

### Kyverno Image Verification Policy
Deploy this Kyverno policy in your Kubernetes cluster to reject any container image that is not signed by your organization's authorized GitHub repository.

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signatures
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: verify-signature-from-github-actions
      match:
        any:
          - resources:
              kinds:
                - Pod
      verifyImages:
        - imageReferences:
            - "ghcr.io/my-org/*"
          attestations: []
          keyless:
            issuer: "https://token.actions.githubusercontent.com"
            subject: "https://github.com/my-org/my-repo/.github/workflows/deploy.yml@refs/heads/main"
```

---

## Tooling and Implementation

Implement a secure supply chain using the following tools:

1. **Trivy / Syft**: Use Syft to generate Software Bills of Materials (SBOMs) in CycloneDX or SPDX formats. Use Trivy to scan the generated SBOMs for known CVE vulnerabilities before building the container.
2. **Cosign**: Use Cosign to sign container images dynamically in your CI/CD pipelines and store the signatures inside your registry.
3. **Kyverno / Connaisseur**: Deploy Kyverno or Connaisseur in your Kubernetes clusters to intercept deployment requests, verify signatures, and block non-compliant container images.

---

## Software Supply Chain Security Audit Checklist

| Item | Focus Area | Verification Step / Command | Target State |
| :--- | :--- | :--- | :--- |
| 1 | SBOM Generation | Check if builds automatically generate CycloneDX or SPDX SBOMs. | Every build output includes a signed SBOM artifact. |
| 2 | Image Verification | Verify if the Kubernetes cluster enforces image signature checks. | Kyverno policies block unsigned images from running in production. |
| 3 | Keyless Signing Issuer | Check the issuer subject constraints in your signing policies. | Verification policies restrict subjects to authorized repo workflows and branches. |
| 4 | Registry Access | Audit access policies for container registries. | Write access is restricted to pipeline roles, and user accounts require MFA. |
| 5 | Lockfile Integrity | Check if package managers enforce lockfile checks during builds. | Node projects build using `npm ci` to prevent dependency changes during compilation. |
| 6 | Provenance Generation | Verify if builds generate SLSA-compliant provenance documents. | Provenance documents are generated and stored alongside build artifacts. |

---

## References

* *SLSA (Supply-chain Levels for Software Artifacts) Specification*: [SLSA Website](https://slsa.dev)
* *Sigstore Cosign Signing and Verification*: [Sigstore Documentation](https://docs.sigstore.dev/cosign/overview/)
* *CycloneDX SBOM Specification*: [CycloneDX Schema](https://cyclonedx.org)
* *NIST Executive Order 14028 (Improving the Nation's Cybersecurity)*: [NIST EO 14028](https://www.nist.gov/itl/executive-order-14028-improving-nations-cybersecurity)
