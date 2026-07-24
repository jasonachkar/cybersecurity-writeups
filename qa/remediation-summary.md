# Remediation summary — PR #5 (`codex/validated-gh-pages-deployment`)

This file records the final remediation architecture for the draft `gh-pages` publication review. It is documentation only.

**Runtime QA JSON files under `qa/*.json` are gitignored.** GitHub Actions artifacts are the authoritative evidence for a checked-out revision. Reports use `sourceCommit`, `sourceTree`, `validatedCommit`, and `validatedTree` (not self-referential `gitCommit` / `gitTree` claims inside committed files).

## Evidence and verification contract

`npm run verify:all` includes:

- static site validation, HTML validation, and known-defect checks
- JavaScript labs (locked `npm ci` where lab lockfiles exist)
- Go `gofmt -d`, `go test`, and `go vet` for maintained modules
- Terraform **1.14.6** fmt/init/validate
- OPA **1.17.0** native per-fixture Rego tests
- Bicep **0.36.1** compile (generated JSON deleted; no Azure deploy)
- Tetragon **1.7.0** and Kyverno ImageValidatingPolicy CRD **1.18.2** schema validation
- native Kyverno CLI **1.18.2** hardened-pod tests
- PostgreSQL RLS disposable integration lab
- ShellCheck **0.10.0**
- PowerShell syntax parse only (CI pins **7.4.6**)
- accessibility (shipped DOM after `portfolio-a11y.js`; the audit does **not** inject accessibility repairs)
- external links
- Gitleaks working-tree and git-history scans (checksum-verified **8.30.0**)
- verification summary and strict provenance gate

CI (`.github/workflows/gh-pages-quality.yml`) splits the same suites across jobs, uploads explicit per-job artifacts, assembles them without filename collisions, and publishes `qa-authoritative-summary`. There is no deployment step.

## Technical corrections retained from earlier phases

| Area | Resolution |
|------|------------|
| AI broker | In-memory `ApprovalStore` CAS; action binding is SHA-256 of canonical JSON (`hashActionBinding`); concurrent/sequential replay and delimiter-collision tests |
| K8s RBAC auditor | `RoleKey` identity; strict `roleRef.apiGroup` / kind / namespace validation; ordinary RoleBinding grants only known namespaced resources; special `bind`/`escalate` modeled separately (including namespaced `bind` on ClusterRoles); identity `impersonate` is ClusterRoleBinding-only; TokenRequest limited to core `serviceaccounts/token`; bounded built-in coverage. The utility is a bounded static teaching heuristic. It does not perform Kubernetes API discovery, SubjectAccessReview, SelfSubjectRulesReview, aggregation analysis or complete effective-permissions evaluation. |
| Accessibility | Production helper labels landmarks via MutationObserver; audit asserts shipped attributes then runs axe |
| 404 page | `site-utility` missing-page experience; not archived guidance |
| Provenance wording | Timeless publication target `gh-pages` / publication review PR #5 |

## Remaining intentional limitations

- Kyverno image signature policy: schema/offline only (not live admission).
- Tetragon: schema validation only (no live cluster enforcement).
- Supply-chain: offline adapter contract only (no production DSSE verification).
- AI ApprovalStore: teaching in-memory CAS (not a distributed durable store).
- No cloud resources deployed during validation.
- PowerShell: syntax-parse only; the script is not executed.
- Some external sites may limit automated link checking.
- K8s RBAC utility: bounded static teaching heuristic covering known built-in risk classes and selected special authorization verbs; it does not perform Kubernetes API discovery, SubjectAccessReview, SelfSubjectRulesReview, aggregation analysis or complete effective-permissions evaluation.

## PR state

PR #5 remains **draft** until an independent reviewer accepts the tip. Do not treat a green finite suite as production authorization or deployment proof.
