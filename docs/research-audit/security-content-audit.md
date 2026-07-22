# Security Content Audit

**Audit date:** 2026-07-21
**Scope:** all authored Markdown, supporting code, repository scripts, MkDocs configuration, and repository-level quality controls
**Inventory:** [Complete page-by-page inventory](content-inventory.md)

## Executive summary

The repository has unusual breadth for a personal portfolio: cloud architecture, identity, Kubernetes, application security, DevSecOps, incident analysis, tutorials, and small Go utilities are all represented. The strongest pages already use threat models, implementation snippets, diagrams, and audit checklists.

The credibility risk is that presentation quality currently exceeds evidence quality. Before this audit, the indexed articles had no review-status metadata, many supporting pages had no metadata at all, most high-risk claims relied on a references list rather than direct citations, and no CI workflow validated examples. Several concrete errors could mislead a practitioner: an invalid PostgreSQL catalog field, unsafe Go transaction handling, signed OIDC claims described as spoofable, deprecated Terraform locking guidance, OAuth audience conflation, overbroad Kubernetes node and DNS statements, and breach claims that mixed confirmed facts with retrospective or speculative controls.

The modernization should therefore prioritize four evidence-backed flagships, correct the high-risk claims wherever they occur, and introduce small reproducible labs and honest test status. It should not attempt to label the whole repository verified in one pass.

## Repository orientation

### Structure and generated content

- `appsec/`, `cloud-security/`, `devsecops/`, and `threat-intel/` contain the newer indexed single-file articles.
- `docs/tutorials/`, `docs/research/`, and `docs/certification-notes/` contain multi-page legacy material whose folder `README.md` files are indexed.
- `scripts/generate-index.js` updates only the marked index block in the root `README.md` and supports both layouts.
- `mkdocs-project/docs/*` includes Git symbolic-link entries. On Windows checkouts without symbolic-link support they appear as small text files containing relative paths; the strict MkDocs build must therefore run on a symlink-capable checkout or recreate those links.
- The repository had no `.github/workflows/`, pull-request template, `AGENTS.md`, package manifest, metadata validator, link checker configuration, or automated code validation at audit start.

### Existing authoritative commands

| Purpose | Command | Audit-start status |
| --- | --- | --- |
| Generate root index | `node scripts/generate-index.js` | Present |
| Markdown and index check | `bash scripts/lint-markdown.sh` | Present; downloads `markdownlint-cli2` through `npx` |
| Strict site build | `mkdocs build -f mkdocs-project/mkdocs.yml --strict` | Present through `scripts/deploy-docs.sh`; requires a pre-created `.venv` and symlinks |
| Example tests | none | Missing |
| Metadata validation | none | Missing |
| Link validation | none | Missing |

## Strengths

- Broad coverage aligns with cloud-security and DevSecOps engineering roles.
- Articles commonly include concrete policies, commands, diagrams, and audit questions instead of only conceptual summaries.
- The domain-based index is automated and backward-compatible with the legacy folder layout.
- Defensive intent is clear; offensive examples are framed as threat explanation.
- The Azure landing-zone tutorial and enterprise-cloud research set contain enough implementation detail to become useful portfolio evidence once validated.
- Existing Go utilities provide a starting point for runnable evidence.

## Weaknesses

- Publication dates were often in the future relative to original content provenance or lacked a documented review event; a date alone did not prove currency.
- Important cloud, protocol, database, and breach claims usually lacked inline citations.
- References included stale `tools.ietf.org` links, at least one misspelled GitHub repository, and moved vendor documentation.
- Large tutorial code fences were illustrative fragments but were not labeled as such or extracted into parser-valid labs.
- No negative test demonstrated a claimed security boundary.
- Operational ownership, exception expiry, rollback, control-health metrics, false-negative detection, and cost were mostly absent.
- The same assertive phrases recur across articles (`full takeover`, `absolute isolation`, `catastrophic`), sometimes beyond what the cited evidence supports.
- The site configuration depends on Git symlinks but does not document the Windows checkout limitation.

## High-risk factual issues

| Severity | File | Finding | Required correction |
| --- | --- | --- | --- |
| Critical credibility issue | `appsec/saas-multitenancy-isolation.md` | Uses nonexistent `pg_class.relforcepayload`; returns `*sql.Rows` after committing the transaction that owns them; middleware accepts raw `X-Tenant-ID` as identity. | Use `relrowsecurity` and `relforcerowsecurity`; consume/copy rows before commit; derive tenant context from a verified server-side principal; add negative isolation tests. |
| Critical credibility issue | `cloud-security/iam-at-scale.md` | Suggests a caller can spoof a signed GitHub OIDC `sub` and that any repository could then assume the role. | Explain that the issuer signs `sub`; risk comes from broad accepted claim patterns, wrong issuer/audience, insufficient branch/environment restriction, or compromised authorized workflow. |
| High-priority technical correction | `devsecops/iac-security-and-policy-as-code.md` | Recommends DynamoDB state locking as the current S3-backend pattern and suggests automatic `terraform apply` for drift. | Prefer S3 `use_lockfile`; call DynamoDB locking deprecated; investigate/classify/approve drift before controlled remediation. |
| High-priority technical correction | `appsec/oauth2-oidc-deep-dive.md` | Treats every token audience as the client ID and cites the OAuth security BCP as an IETF draft. | Separate ID-token client audience from access-token resource-server audience; update to RFC 9700 and finalized PAR, DPoP, and mTLS RFCs. |
| High-priority technical correction | `cloud-security/kubernetes-multi-tenancy.md` | States node credentials can pull secrets across the cluster and that DNS exposes all services; conflates cgroups with namespaces. | Limit Node-authorizer secret access to pods bound to that node; describe DNS name resolution without claiming an enumeration API; separate resource control, namespaces, kernel isolation, and authorization. |
| High-priority technical correction | `threat-intel/cloud-breach-case-studies.md` | Presents absence of IMDSv2 as a 2019 Capital One failure although IMDSv2 launched in November 2019; overstates Uber impact and adds unconfirmed PAM/MFA details. | Separate evidence available at the time from retrospective defense in depth; use organization and legal primary accounts; label unknowns. |
| High-priority technical correction | `devsecops/secure-cicd-pipeline-design.md` | Describes fork PR token/secrets behavior as unconditional and proposes a privileged artifact consumer without a full artifact-trust warning. | State repository/fork/event/settings conditions; treat all fork-produced artifacts and caches as untrusted data; never execute them in the privileged phase. |
| Medium-priority modernization | `devsecops/supply-chain-sbom-signing.md` | Uses mutable action tags and an older Kyverno verification shape; implies signing proves security. | Pin third-party actions by full SHA in runnable examples; distinguish integrity/provenance from vulnerability absence; verify signer identity, issuer, digest, and builder policy. |

## Stale standards and deprecated guidance

- OAuth Security Best Current Practice is finalized as RFC 9700, replacing draft references.
- Terraform S3 backend DynamoDB locking is deprecated; S3 lockfiles are the current HashiCorp-documented option.
- SLSA v1.2 is current at review time; articles must qualify claims against an explicit track, level, and version.
- OWASP Top 10:2025 supersedes the 2021 awareness list. OWASP API Security Top 10 remains the 2023 edition.
- OWASP ASVS 5.0.0 is final. ASVS 4.0.3 references should be retained only when intentionally historical.
- Microsoft Cloud Security Benchmark v1 remains the final baseline; MCSB v2 is preview and must not be described as final.
- MITRE ATT&CK v19.1 is current as of 2026-07-21. Technique mappings should record the ATT&CK version reviewed.
- NIST IR 8547 remains a draft transition plan; FIPS 203, 204, and 205 are finalized PQC standards.

The exact versions, dates, dispositions, and primary links are maintained in `docs/standards/security-standards-review.md` so future reviews can update one evidence table.

## Weak or unverifiable references

- A misspelled Principal Mapper link (`pmpper`) undermines the IAM article even though the intended project is identifiable.
- `docs.microsoft.com` links should move to canonical `learn.microsoft.com` targets.
- `tools.ietf.org` RFC links should use canonical RFC Editor URLs.
- General vendor marketing or blog pages should not support protocol requirements or breach root-cause statements when standards, legal filings, or official incident reports exist.
- Several legacy pages make statistics or product-behavior claims without a source. They must be removed, directly cited, or marked for review; a references section elsewhere in the page is insufficient.

## Articles requiring urgent correction

1. SaaS Multi-Tenancy Isolation Patterns (`appsec/saas-multitenancy-isolation.md`)
2. Enterprise IAM at Scale (`cloud-security/iam-at-scale.md`)
3. OAuth 2.0 and OIDC Security Deep Dive (`appsec/oauth2-oidc-deep-dive.md`)
4. IaC Security and Policy as Code (`devsecops/iac-security-and-policy-as-code.md`)
5. Kubernetes Multi-Tenancy (`cloud-security/kubernetes-multi-tenancy.md`)
6. Cloud Breach Case Studies (`threat-intel/cloud-breach-case-studies.md`)
7. Secure CI/CD Pipeline Design (`devsecops/secure-cicd-pipeline-design.md`)
8. Software Supply Chain Security (`devsecops/supply-chain-sbom-signing.md`)

## Recommended flagships

| Flagship | Why it is portfolio-relevant | Evidence target |
| --- | --- | --- |
| Azure Landing Zone Security | Demonstrates governance, identity, networking, platform ownership, and policy tradeoffs. | Parser-valid Bicep, an OIDC deployment workflow, policy/management-group validation, and deployment/rollback criteria. |
| Secure CI/CD Pipeline Design | Demonstrates adversarial thinking about the delivery control plane. | Safe and unsafe expression interpolation fixtures, minimal permissions, fork trust model, and scanner-failure tests. |
| Software Supply Chain Security | Demonstrates integrity from source through admission. | SBOM schema validation, digest/action pinning, provenance policy, and an unsigned-artifact negative test. |
| SaaS Multi-Tenancy and PostgreSQL RLS | Demonstrates a concrete authorization boundary and failure testing. | Migration/runtime role separation plus cross-tenant, missing-context, pool-reuse, owner, privileged-role, and missing-RLS tests. |

## Recommended automation improvements

1. Validate index-page metadata and enumerated values without pretending to validate truth.
2. Generate this inventory and fail when it is stale.
3. Check links and anchors with documented exclusions for hosts that block automation.
4. Warn on freshness using content-specific review intervals.
5. Parse YAML/JSON and validate extracted labs with their native tools.
6. Build Go utilities individually because each script directory contains multiple standalone `main` programs.
7. Scan workflow permissions, mutable third-party action references, and obvious secrets.
8. Build MkDocs on Linux where tracked symlinks resolve correctly.

## Prioritized remediation backlog

### Critical credibility issues

- Correct and test the PostgreSQL RLS implementation and catalog queries.
- Correct the OIDC signed-claim threat model and trust-policy examples.

### High-priority technical corrections

- Modernize Terraform locking/drift guidance, OAuth/OIDC standards, Kubernetes isolation claims, and all three breach timelines.
- Add direct primary citations beside each corrected claim.
- Extract at least one fully executable negative-test lab.

### Medium-priority modernization

- Upgrade the four flagships with scope, decisions, failure modes, ownership, rollout/rollback, validation, observability, cost, and residual risk.
- Add metadata status and validation tooling to every indexed article.
- Add a standards review, source policy, authoring guide, and SecureObs-derived sanitized engineering case study.
- Add CI checks and a PR template.

### Low-priority editorial improvement

- Replace generic or absolute wording where the architecture does not justify it.
- Normalize canonical links and naming (`Microsoft Entra ID`, canonical RFC Editor links).
- Reduce duplicated material by linking supporting legacy pages to verified flagships instead of copying claims.

## Audit limitations

- Structural inventory can be automated; factual verification cannot. `content-inventory.md` intentionally labels unreviewed pages as requiring manual review.
- Cloud product behavior that requires a paid tenant/account is verified against current vendor documentation but is not described as independently tested.
- A reachable URL shows availability, not source quality or correctness.
- The audit does not claim that all legacy certification notes have been re-researched. They remain useful study material but are not flagship evidence until individually reviewed.
