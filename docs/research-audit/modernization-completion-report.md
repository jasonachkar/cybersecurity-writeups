# Security Content Modernization Report

## Executive summary

This branch converts the repository's highest-risk security guidance into
evidence-labeled engineering content with runnable positive and negative tests. It
also replaces the stale, manual Pages path with a validation-gated build and
publication workflow that records the exact source revision in every generated
page.

No production cloud resources were created. No customer or employer implementation
evidence is claimed. The public site was not changed from this branch: publication
is deliberately restricted to a validated push to `main` after review and merge.

## Branches inspected

The repository and remote branch topology were inspected before implementation:

| Branch | Inspected tip | Finding |
| --- | --- | --- |
| `origin/main` | `fe2bb5fcaccecea7533ade47f2bb7da7d30213af` | Authoritative source; contains the previous modernization merge |
| `origin/codex/senior-security-content-modernization` | `811cb9ef8903fe6d65114f7794ca7cc40a36ae07` | Source of the prior reviewed content and lab baseline |
| `origin/feature/docs-update` | `50daf4e195c93b02552205925c997213eb24a2cf` | Historical documentation work |
| `origin/research/enterprise-cloud-security-engineering` | `6c376f5cb8607162de0a63bdc9f927054d54068a` | Historical research branch |
| `origin/gh-pages` | `dd22b653ce7b8776969508884caea40675c7489f` | Generated site last updated 2026-06-28 |
| `codex/production-security-content-verification` | Based on `origin/main`; PR head is the review revision | This implementation branch |

The authored-page inventory and risk classification are in
[`docs/research-audit/security-content-audit.md`](security-content-audit.md) and the
generated [`docs/research-audit/content-inventory.md`](content-inventory.md).

## Deployment issue discovered

The live Pages source was the legacy `gh-pages` branch, but the content-quality
workflow only validated source; it did not publish the successful `main` build.
`origin/gh-pages` recorded `Deployed 5937b22 with MkDocs version: 1.6.1`, resolving
to source commit `5937b22a83ce113f0e5a2c6b5e51b17f61c01b69`, while current `main` was
`fe2bb5fcaccecea7533ade47f2bb7da7d30213af`.

The public site returned `404` for `/site-meta.json` and for pages introduced after
the June build. Its HTML linked to the repository but did not expose a full source
SHA or build timestamp. GitHub Pages remained configured for `gh-pages:/`; HTTPS
enforcement was not enabled in repository Pages settings.

## Deployment architecture implemented

The corrected path is implemented in:

- `.github/workflows/content-quality.yml`
- `.github/workflows/site-freshness.yml`
- `scripts/prepare-mkdocs.js`
- `scripts/validate-generated-site.js`
- `scripts/publish-gh-pages.sh`
- `scripts/check-deployed-site.js`
- `scripts/deploy-docs.sh`
- `mkdocs-project/mkdocs.yml`
- `mkdocs-project/overrides/partials/copyright.html`

Pull requests run validation, build a clean strict-mode MkDocs tree, validate it,
and upload a seven-day preview artifact. They cannot deploy.

A push to `main` deploys only after content validation, the PostgreSQL integration,
the strict documentation build, and secret scanning succeed. The deployment job:

1. downloads the exact same-run validated site artifact;
2. revalidates its source SHA and generated invariants;
3. checks out `gh-pages` separately;
4. deletes its tracked stale output;
5. copies only the clean validated tree;
6. commits and pushes normally, without force;
7. explicitly requests the legacy Pages build; and
8. polls the public provenance until the expected SHA is visible.

The workflow's default permission is `contents: read`. Only the main-only publisher
receives `contents: write` and `pages: write`. Third-party actions are pinned to full
commit SHAs.

`site-meta.json`, the Build Provenance page, and every page footer expose:

- full source commit SHA and link;
- source branch;
- UTC build timestamp;
- repository link; and
- machine-readable provenance link.

The generated-site validator rejects the stale sentinel, symlinks, missing CNAME or
`.nojekyll`, wrong provenance, duplicate or wrong canonical URLs, sitemap drift,
missing source footers, and stale pages retained by a non-clean build.

## High-risk technical corrections

### IAM and workload identity

Updated:

- `cloud-security/iam-at-scale.md`
- `docs/research/enterprise-cloud-security-engineering/iam-workload-identity.md`
- `labs/iam-oidc/`

The guidance now separates four decisions that are frequently conflated:

1. token signature validation;
2. issuer, audience, time, and subject-claim validation;
3. role or federated-credential trust evaluation; and
4. downstream permission evaluation.

The 45-case evaluator covers exact GitHub branch and environment subjects, Azure
federated credentials, EKS IRSA, third-party external ID and constrained session
tags, permissions-boundary create/remove/replace paths, restricted `PassRole`, and
post-assumption permission denial. Simulator limitations and provider/runtime
boundaries are explicit.

### CI/CD security

Updated:

- `devsecops/secure-cicd-pipeline-design.md`
- `labs/secure-cicd/`

The article accurately distinguishes the trusted base-branch workflow definition
from attacker-controlled data and checked-out code under `pull_request_target`.
Secret availability is described as dependent on event, fork, permission,
environment, and repository settings rather than as a universal behavior.

The positive workflow separates untrusted PR validation from a protected trusted
build/release path. Tests require full-SHA actions, least token permissions,
revision-bound artifacts, digest and attestation verification before OIDC
authentication, environment binding, no long-lived cloud credential, and no
cross-boundary cache execution. Negative fixtures exercise privileged unverified
artifact consumption and cache poisoning.

### PostgreSQL RLS and tenant isolation

Updated:

- `appsec/saas-multitenancy-isolation.md`
- `labs/postgresql-rls/README.md`
- `labs/postgresql-rls/init/001-schema.sql`
- `labs/postgresql-rls/tests/rls-tests.sql`
- `labs/postgresql-rls/tests/boundary-tests.sql`
- `labs/postgresql-rls/tests/catalog-tests.sql`
- `labs/postgresql-rls/run-tests.ps1`
- `labs/postgresql-rls/run-tests.sh`

The lab uses transaction-local tenant context, complete `USING` and `WITH CHECK`
expressions, `ENABLE` plus `FORCE ROW LEVEL SECURITY`, and non-bypass runtime and
owner roles. PostgreSQL 18.4 integration tests reject cross-tenant reads, updates,
inserts, tenant-key mutation, missing/malformed context, connection reuse leakage,
owner bypass, extra policies, unexpected policy roles, and trivially true/missing
expressions.

The guidance explicitly treats background jobs as tenant-scoped transactions or
separately reviewed maintenance identities; it does not grant an implicit
system-wide tenant.

### Terraform and policy as code

Updated:

- `devsecops/iac-security-and-policy-as-code.md`
- `labs/iac-policy/`

The S3 backend uses current `use_lockfile = true` guidance. DynamoDB-based locking is
identified as deprecated, and state sensitivity, version recovery, KMS, access,
logging, and bootstrap controls are separated from the backend block.

Terraform 1.14.6 formatting and offline initialization/validation pass for the
hardened and intentionally insecure backends. OPA 1.17.0 Rego v1 tests cover accepted
plans and denial for public storage, missing storage controls, public networking,
public/unencrypted databases, wildcard IAM, missing authorization tags, unknown
security values, and deletion of a modeled control.

### Kubernetes security

Updated:

- `cloud-security/kubernetes-multi-tenancy.md`
- `labs/kubernetes-security/`

The guidance distinguishes soft namespace boundaries from hostile-tenant
isolation, and separates admission, network, node/runtime, identity, availability,
and observability enforcement.

Kyverno CLI 1.18.2 validates the current
`policies.kyverno.io/v1` `ValidatingPolicy` against one accepted and six rejected
Pod fixtures. The current `ImageValidatingPolicy` structure binds repository,
issuer, full workflow identity, digest, and SLSA provenance. Ten identity-model
cases reject unsigned, wrong repository/workflow/branch/issuer, absent or malformed
provenance, mutable-tag, and digest-substitution inputs. The evidence does not claim
an API-server, registry, Sigstore, transparency-log, or CNI integration test.

### Software supply chain and SLSA

Updated:

- `devsecops/supply-chain-sbom-signing.md`
- `labs/supply-chain/`
- `.gitattributes`
- `scripts/validate-reproducible-fixtures.js`

The guidance identifies SLSA v1.2, the Build track, and target-level semantics rather
than using an unversioned universal maturity claim. SBOM, digest, signature,
attestation, builder, source, and policy decisions remain separate evidence.

The offline lab binds an exact LF-stable artifact SHA-256, SLSA predicate fields,
builder/build type/source policy, and external-verifier result. It rejects digest
tampering, unauthorized builder, build type, source/workflow identity, issuer,
missing run details, failed cryptographic verification, and a verifier result bound
to a different statement. It explicitly does not implement Sigstore cryptography.

### OAuth and OIDC

Updated:

- `appsec/oauth2-oidc-deep-dive.md`
- `appsec/scripts/oauth-pkce-verifier.go`
- `docs/research/oauth-misconfigurations/code-examples.md`
- `labs/oauth-oidc/`

The Go PKCE example is S256-only, validates the RFC 7636 verifier length and
unreserved syntax, uses a constant-time comparison, uses cryptographic randomness,
and never logs verifier or challenge values.

The dependency-free Node.js model runs 14 acceptance/rejection cases for signature,
issuer, string/array audience, expiry, not-before, tenant, scope, bounded key
rotation, retired/unknown key IDs, and exact redirect registration/matching. The Go
program runs eight PKCE checks including the RFC vector and downgrade/syntax
negatives. The legacy unsafe normalization examples were replaced with an evidence
and migration page.

### AI and agent security

Added:

- `appsec/ai-agent-security.md`
- `labs/ai-agent-security/broker.js`
- `labs/ai-agent-security/tests/broker.test.js`
- `labs/ai-agent-security/README.md`

The flagship treats prompts, retrieved content, memory, tool metadata, and model
outputs as untrusted proposals. System prompts and content filters are explicitly
not authorization boundaries.

The tool broker enforces authenticated principal, tenant and tool allowlists,
typed arguments, amount/destination constraints, separately bound high-impact
approval, approval replay prevention, a control-plane kill switch, and redacted
audit outcomes. Nine tests exercise allowed and denied paths.

## Validation tooling added

- `scripts/validate-claims.js`: deterministic strong-claim scan and review queue.
- `scripts/run-lab-tests.js`: discovers every executable JavaScript lab suite.
- `scripts/run-go-self-tests.js`: runs the PKCE and redacting scanner self-tests.
- `scripts/validate-native-policies.js`: requires pinned OPA/Kyverno in CI.
- `scripts/validate-reproducible-fixtures.js`: enforces exact supply-chain bytes.
- `scripts/run-rls-lab.js`: cross-platform disposable database integration entry.
- `scripts/validate-code-examples.js`: parses JSON/YAML/JavaScript, compiles every
  standalone Go file, formats and validates Terraform, and invokes available
  Bicep, ShellCheck, and PowerShell checks.
- `scripts/content-lib.js`: excludes ignored build/tool trees from source checks.
- `scripts/prepare-mkdocs.js` and `scripts/validate-generated-site.js`: deterministic
  staging and generated-site invariants.
- `.gitattributes`: stable LF rules plus a non-normalized signed artifact fixture.
- `.markdownlint-cli2.jsonc`: excludes generated and tool-cache trees.

`package.json` exposes the complete local entry points and `npm run validate`
orchestrates the content, source, fixture, lab, and policy gates.

## Automated tests added

Local evidence recorded on 2026-07-23:

| Test area | Result |
| --- | --- |
| JavaScript lab programs | 8/8 programs passed |
| AI broker | 9/9 passed |
| IAM/OIDC evaluator | 45 evaluations passed |
| CI/CD boundary model | 7 hardened/unsafe boundary pairs passed |
| OAuth/OIDC model | 14/14 passed |
| OPA Rego v1 | 5/5 assertions passed |
| Native Kyverno Pod policy | 7/7 expected cases passed |
| Kubernetes image identity model | 10 cases passed |
| Go PKCE program | 8/8 checks passed |
| Go secret scanner | synthetic findings detected and redacted; benign/context/removal behavior passed |
| Standalone Go compilation | 10/10 files compiled |
| Terraform | 3 files format-clean; 2 lab backends initialized offline and validated |
| PostgreSQL RLS | PostgreSQL 18.4 runtime, boundary, and catalog suites passed |
| Supply-chain exact bytes | SHA-256 `096407aa951a20498aabd46de33f6c41f190fc7987d3e01779438afc5c65b1c9` passed |
| Action pins | 13 authoritative YAML files passed |
| Strict generated site | 108 HTML pages passed provenance/canonical/sitemap/stale checks before the final generated refresh |

The final draft-PR checks are the authoritative cross-platform result. ShellCheck
was unavailable in the Windows local environment and is mandatory in the Ubuntu CI
job.

## Positive fixtures

- Exact GitHub branch/environment OIDC subjects, Azure federated credential, IRSA,
  external-ID session, bounded role creation, and restricted `PassRole`.
- Unprivileged PR validation and protected trusted build/release workflow.
- Tenant A and Tenant B rows with transaction-scoped context.
- Hardened Terraform S3 backend and accepted serialized plan.
- Hardened Pod, default-deny network policy, exact image identity/digest/provenance.
- Valid supply-chain artifact, provenance, external-verifier result, and CycloneDX
  SBOM.
- Correctly signed OAuth access token, rotation overlap, registered redirect, and
  RFC 7636 S256 vector.
- Authorized low-impact agent tool call and separately approved high-impact call.

## Negative fixtures

- Invalid signature; wrong/missing issuer, audience, subject, external ID, or tags;
  permissions boundary removal/replacement; unrestricted `PassRole`; downstream
  permission denial.
- `pull_request_target` attacker-head execution, mutable actions, write-all tokens,
  unverified privileged artifacts, stored cloud credential references, missing
  environment binding, and shared executable cache.
- Cross-tenant select/update/insert/tenant-key mutation; missing or malformed tenant
  context; owner bypass; extra or trivially true policy.
- Public or uncontrolled storage/network/database/IAM; unknown values; deleted
  security control.
- Privileged/host namespace/hostPath/capability/missing-resource/token-automount
  Pods; wrong/unsigned/mutable image evidence.
- Artifact tamper, wrong builder/build type/source/issuer, failed verifier, missing
  run details, and mismatched verifier statement.
- OAuth bad signature/issuer/audience/time/tenant/scope/key/redirect; PKCE plain,
  wrong verifier, malformed challenge, and invalid verifier syntax.
- Unauthorized tenant/tool/destination/amount, missing or mismatched approval,
  replay, unknown arguments, and active kill switch.

## Flagship investigations

The three primary investigations are:

1. `devsecops/secure-cicd-pipeline-design.md` with `labs/secure-cicd/`;
2. `appsec/saas-multitenancy-isolation.md` with `labs/postgresql-rls/`; and
3. `devsecops/secureobs-multitenant-security-scanner.md`, explicitly separating
   owner-confirmed architecture, repository-reproduced patterns, and recommendations.

`appsec/ai-agent-security.md` and `labs/ai-agent-security/` add a fourth current
investigation focused on authorization outside the model.

## Homepage and navigation changes

`README.md` now leads with evidence labels, flagship investigations, validated labs,
architecture research, tutorials, and separately labeled study notes. It does not
imply that every article is deployed or based on enterprise production ownership.

`mkdocs-project/mkdocs.yml` adds AI Agent Security and SecureObs to the primary
navigation. SC-500 now uses the current four skill groups and points Domain 3 to
secure compute and Domain 4 to managing and monitoring security posture. Obsolete
paths remain as clearly superseded pages rather than silently disappearing.

## Standards and primary sources

High-risk corrections were reviewed against primary sources, including:

- AWS IAM, STS, Organizations, EKS IRSA, and IAM policy-evaluation documentation;
- Microsoft Entra workload identity federation and the official SC-500 study guide;
- GitHub Actions events, secure use, OIDC, artifact attestations, environments, and
  Pages documentation;
- PostgreSQL row-security, role, and catalog documentation;
- Terraform S3 backend, state sensitivity, and JSON plan documentation;
- Kubernetes security, admission, NetworkPolicy, and service-account documentation;
- Kyverno 1.18 policy-type and image-verification documentation;
- SLSA v1.2, CycloneDX 1.7, SPDX 3.0, Sigstore, and in-toto specifications;
- RFC 7636, RFC 8252, RFC 8725, RFC 9700, and OpenID Connect Core; and
- NIST AI RMF, GenAI Profile, SSDF AI profile, and OWASP agent/LLM guidance where
  normative status is stated accurately.

## Commands to validate locally

Install the locked JavaScript dependencies:

```text
npm ci --ignore-scripts
```

Refresh deterministic generated sources after content changes:

```text
npm run index:generate
npm run claims:generate
```

Run the top-level content, source, fixture, and lab gate:

```text
npm run validate
```

Require the same native tool presence as CI:

```powershell
$env:REQUIRE_CODE_TOOLCHAINS = "1"
$env:REQUIRE_NATIVE_SECURITY_TOOLS = "1"
npm run validate
```

Run the disposable PostgreSQL integration:

```text
npm run rls:test
```

With the documented Python virtual environment and pinned requirements installed,
build and validate the site without publishing:

```text
./scripts/deploy-docs.sh
```

Focused commands are documented in each lab README. The repository-level native
policy entry is:

```text
npm run policies:test
```

## Deployment verification procedure

1. Review and merge the draft PR only after all required checks pass.
2. Confirm the `main` run completes `validate`, `postgresql-rls`, `docs-build`,
   `secret-scan`, and `deploy-site`.
3. Record the merged `main` SHA.
4. Confirm `origin/gh-pages` advances by a normal deployment commit.
5. Fetch `https://docs.jasonachkardiab.com/site-meta.json`.
6. Verify `sourceBranch` is `main`, `sourceCommit` equals the merged SHA, the
   timestamp is UTC and current, and the repository field is exact.
7. Open the Build Provenance page and a content page; confirm both display the full
   SHA, timestamp, repository link, and correct canonical URL.
8. Confirm removed paths are absent and the sitemap/canonical sets match.
9. Run the read-only checker:

```powershell
$env:SITE_SOURCE_BRANCH = "main"
$env:SITE_SOURCE_COMMIT = (git rev-parse origin/main)
node scripts/check-deployed-site.js
```

No deployed source SHA is reported here because this branch was not merged or
published during local validation.

## Remaining limitations

- The public site remains the stale June build until this PR is reviewed, merged,
  and the gated `main` deployment succeeds. This report does not claim otherwise.
- The strong-claim report is a deterministic triage queue, not proof that every
  legacy sentence has completed expert review. High-risk pages were corrected
  first; lower-risk legacy pages remain visible in the inventory.
- Local Windows validation lacked ShellCheck. CI installs or requires the Ubuntu
  runner toolchain and is the cross-platform authority.
- IAM, Azure federation, GitHub environment protection, online Sigstore/Kyverno
  image verification, Kubernetes API/CNI behavior, and cloud-provider policy
  enforcement need non-production integration tests in their owning environments.
- Terraform plans are reviewed fixtures and do not contact AWS. The Azure
  landing-zone Bicep check parses/builds templates but does not deploy resources.
- The OAuth/OIDC verifier is an educational model, not a replacement for a
  maintained JOSE/OIDC library or provider conformance suite.
- The RLS lab does not model managed-database administrator roles, application
  connection-pool middleware, replication, backups, or side channels.
- SecureObs private implementation details, signed scanner distribution, and
  production telemetry are not available in this public repository; recommendations
  remain labeled as such.
- Pages HTTPS enforcement and branch/ruleset policy are repository settings outside
  this source-only change.

## Follow-up recommendations

1. Require the content-quality, PostgreSQL, documentation, and secret-scan checks in
   a `main` branch ruleset before allowing merge.
2. Enable Pages HTTPS enforcement after confirming the custom-domain certificate.
3. Run GitHub/Azure/AWS OIDC exchange tests with dedicated non-production identities
   and inspect cloud audit logs for accepted and rejected subjects.
4. Add an online signed/unsigned image test against an organization-owned registry
   before enforcing the Kyverno image policy in a cluster.
5. Exercise tenant context through the real application connection pool and
   background-job framework.
6. Continue the generated strong-claim queue by risk order and record bounded
   evidence comments next to reviewed statements.
7. Refresh pinned tool versions, action SHAs, primary-source review dates, and
   certification objectives on a scheduled cadence.
