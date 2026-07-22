---
title: "Security standards and platform currency review"
type: "research"
tags:
  - standards
  - governance
  - secure-development
date: "2026-07-21"
lastReviewed: "2026-07-21"
readingTime: 24
reviewStatus: "verified"
validatedAgainst:
  - "Primary standards and vendor sources listed in References, checked 2026-07-21"
sourceQuality: "primary-sources-reviewed"
implementationStatus: "illustrative"
reviewIntervalDays: 90
---

# Security standards and platform currency review

This matrix is the repository's dated baseline for security standards and selected
platform guidance. It records what is final, what is still draft or preview, and how
authors should cite it. A living publication can change without a numbered release;
articles must still record the date reviewed.

## Application and API security

| Publication | Status checked 2026-07-21 | Repository use |
| --- | --- | --- |
| OWASP Top 10 | **2025** is the current released edition. | Awareness and risk taxonomy; not a verification standard or exhaustive test plan. |
| OWASP ASVS | **5.0.0**, released 2025-05-30, is current. | Preferred application-security requirements and verification vocabulary. Pin requirement identifiers to the stated ASVS version. |
| OWASP API Security Top 10 | **2023** is current. | API risk awareness; pair with testable ASVS or organization-specific requirements. |
| OWASP SAMM | **v2** is a living maturity model. | Program capability and improvement planning. Do not invent a later point version. |
| OAuth Security BCP | **RFC 9700**, final, January 2025. | Current OAuth security baseline: exact redirect matching, PKCE, authorization-code protections, access-token audience restriction, and refresh-token replay defense. It obsoletes older BCP guidance in RFCs 6749 and 6750 where stated. |
| OpenID Connect Core | **OpenID Connect Core 1.0 incorporating errata set 2**, final. | ID-token semantics and validation. Distinguish an ID token's client audience from an access token's resource-server audience. |
| FAPI 2.0 Security Profile | **Final**, approved February 2025. | High-value API profile. Do not cite an older Implementer's Draft as if it were the final profile. |
| DPoP / OAuth mTLS / PAR | **RFC 9449**, **RFC 8705**, and **RFC 9126**, all final RFCs. | Sender-constrained tokens and pushed authorization requests. Explain operational key, proxy, and replay trade-offs. |

## Secure software development and supply chain

| Publication | Status checked 2026-07-21 | Repository use |
| --- | --- | --- |
| NIST SSDF | **SP 800-218 v1.1** is final. **SP 800-218 Rev. 1 / SSDF 1.2** was published as an Initial Public Draft in December 2025. | Use v1.1 for normative current mappings; clearly label 1.2 material draft until NIST publishes a final revision. |
| NIST AI SSDF profile | **SP 800-218A**, final July 2024. | AI model development-specific augmentation; not a replacement for the base SSDF. |
| SLSA | **v1.2** is current. | Describe build-track provenance levels and verification policy. A provenance statement is evidence, not proof that an artifact is non-malicious. |
| CycloneDX | **1.7** is current. | Preferred current CycloneDX schema when authoring new examples; declare the exact schema in fixtures. |
| SPDX | **3.0** is current. | Use for SPDX 3 examples; identify legacy SPDX 2.x examples rather than silently mixing models. |
| in-toto | Living project/specification. | Supply-chain layout and attestation concepts. Record the specification or statement version used by an implementation. |
| Sigstore Cosign | Living tool and format ecosystem. | Verification must bind digest plus expected identity and issuer. A successful signature check alone does not establish authorization or artifact safety. |
| OpenSSF Scorecard | Living checks and GitHub Action. | Signal for dependency/project hygiene, not a binary trust score. Pin the action by commit SHA and interpret checks individually. |

## Cloud, containers, and service architectures

| Publication | Status checked 2026-07-21 | Repository use |
| --- | --- | --- |
| Azure landing zones | Current Cloud Adoption Framework guidance; landing-zone design areas and subscription vending are living guidance. | Treat the portal accelerator and IaC implementations as implementation choices, not the architecture itself. Record review date and deployment module release. |
| Microsoft cloud security benchmark | **MCSB v1** is the published benchmark; **v2** is preview. | Use v1 for current control mappings. Preview v2 may be discussed only with a preview label. |
| AWS Security Reference Architecture | Living prescriptive guidance; document history records a significant update on 2025-12-22. | Date every architecture citation. Adapt it to risk and organization structure; it is not a deploy-without-review template. |
| AWS Well-Architected Security Pillar | Current revision/publication shown as 2024-11-06. | Design-review questions and practices, not certification evidence. |
| Kubernetes Pod Security Standards | Current Kubernetes standard with Privileged, Baseline, and Restricted profiles. | Prefer Pod Security Admission or a policy engine. PodSecurityPolicy was removed in Kubernetes 1.25. |
| Kubernetes ValidatingAdmissionPolicy | Stable since Kubernetes 1.30. | Native CEL-based admission control. Test `failurePolicy`, parameter absence, exclusions, and version compatibility. |
| NIST microservices guidance | **SP 800-204C**, final March 2022, and **SP 800-204D**, final February 2024. | 204C covers service-mesh-based security; 204D covers DevSecOps implementation for cloud-native applications. |

## Threat intelligence and secure-by-design guidance

| Publication | Status checked 2026-07-21 | Repository use |
| --- | --- | --- |
| MITRE ATT&CK | **v19.1**, released 2026-04-28. | Pin technique mappings to v19.1 or state the later version and date actually reviewed. ATT&CK describes observed behavior; it does not assign control effectiveness. |
| MITRE ATLAS | Living knowledge base with monthly release cadence announced in 2026. | Record review date. Do not present a transient technique count as a durable version identifier. |
| CISA Known Exploited Vulnerabilities Catalog | Living catalog. | Prioritization signal for known exploitation. Record catalog access date and do not treat absence as proof of no exploitation. |
| CISA Secure by Design | Living guidance and pledge/program material. | Product-security principles. Distinguish voluntary guidance or pledges from binding legal requirements. |

## Cryptography and post-quantum transition

| Publication | Status checked 2026-07-21 | Repository use |
| --- | --- | --- |
| NIST PQC standards | **FIPS 203, 204, and 205**, final 2024-08-13. | Current ML-KEM, ML-DSA, and SLH-DSA standards. Use exact algorithm/parameter-set names and rely on validated libraries rather than implementing primitives. |
| NIST key-encapsulation guidance | **SP 800-227**, final 2025-09-18. | KEM use and key-confirmation guidance. |
| NIST transition material | **IR 8547** remains an Initial Public Draft; **CSWP 39 update 1** is final 2026-06-29. | Label IR 8547 draft. Use the final white paper for migration considerations while tracking later NIST transitions. |

## Version-sensitive implementation baseline

These versions are recorded for the companion labs, not declared universal minimums:

| Component | Validated or targeted version | Notes |
| --- | --- | --- |
| PostgreSQL | Lab image `postgres:18.4-alpine3.24`; PostgreSQL 18.4 current when checked. | RLS semantics also cite current PostgreSQL manuals. Superusers and `BYPASSRLS` roles bypass RLS; table owners normally bypass unless `FORCE ROW LEVEL SECURITY` is used. |
| Terraform CLI | Repository validation used 1.14.6 when available locally. | S3 backend guidance uses `use_lockfile`; DynamoDB-based locking is deprecated. |
| Kubernetes client | Repository validation used kubectl 1.34.1 when available locally. | Server-side policy behavior still requires a compatible cluster. |
| Node.js | Repository content validation used Node.js 24.12.0. | CI pins a supported runtime line and locks npm dependencies. |

## Review decisions applied to this repository

1. Draft NIST SSDF 1.2 and Microsoft cloud security benchmark v2 are explicitly
   labeled draft/preview and are not the normative mapping baseline.
2. OAuth articles use RFC 9700 rather than the obsolete OAuth 2.0 Security Best
   Current Practice draft URL.
3. Supply-chain articles use SLSA v1.2, CycloneDX 1.7, and SPDX 3.0 while labeling
   older fixture formats where preserved.
4. Kubernetes material no longer recommends removed PodSecurityPolicy and avoids
   overstating node authorization, DNS discovery, or container isolation.
5. Post-quantum material distinguishes final FIPS and SP publications from draft
   transition documents.

## Maintenance procedure

Review this page every 90 days and whenever a referenced standards body publishes a
new final edition. The reviewer must visit the canonical source, update the status
and date, identify affected articles with the content inventory, and avoid promoting
a draft merely because it has a newer number.

## References

- [OWASP Top 10](https://owasp.org/Top10/)
- [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP API Security Project](https://owasp.org/API-Security/)
- [OWASP SAMM model](https://owaspsamm.org/model/)
- [RFC 9700: Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700.html)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0-18.html)
- [FAPI Working Group final specifications](https://openid.net/wg/fapi/specifications/)
- [NIST SP 800-218: Secure Software Development Framework](https://csrc.nist.gov/pubs/sp/800/218/final)
- [NIST SP 800-218A](https://csrc.nist.gov/pubs/sp/800/218/a/final)
- [SLSA v1.2 specification](https://slsa.dev/spec/v1.2/)
- [CycloneDX specification overview](https://cyclonedx.org/specification/overview/)
- [SPDX specifications](https://spdx.dev/use/specifications/)
- [Azure landing zones](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/)
- [Microsoft cloud security benchmark](https://learn.microsoft.com/en-us/security/benchmark/azure/)
- [AWS Security Reference Architecture document history](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/doc-history.html)
- [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Kubernetes ValidatingAdmissionPolicy](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [NIST SP 800-204C](https://csrc.nist.gov/pubs/sp/800/204/c/final)
- [NIST SP 800-204D](https://csrc.nist.gov/pubs/sp/800/204/d/final)
- [MITRE ATT&CK versions](https://attack.mitre.org/resources/versions/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CISA Secure by Design](https://www.cisa.gov/securebydesign)
- [NIST post-quantum cryptography publications](https://csrc.nist.gov/Projects/post-quantum-cryptography/publications)
- [PostgreSQL versioning policy and supported releases](https://www.postgresql.org/support/versioning/)
