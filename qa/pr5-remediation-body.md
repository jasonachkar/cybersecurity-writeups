# Validated gh-pages remediation — PR #5

## Scope
Only `codex/validated-gh-pages-deployment` → `gh-pages`. No deployment occurred during validation. PR remains draft until all required workflow jobs are green on the latest head.

## Exact head
- **gitCommit:** `000245e681fcbf1cd6dfc359df880038f9844362`
- **gitTree:** `d557a95eadaf6fdf3b494c9e9573427284b04924`
- Local QA regeneration used `QA_ALLOW_DIRTY=1` after intermediate report writes; **CI regenerates reports on a clean checkout** and is authoritative.

## Senior-level content / evidence corrections (this remediation pass)
- AI broker: atomic `ApprovalStore.consumeIfUnused`; concurrent replay test (exactly one executor invocation).
- Docs bound replay to local in-memory CAS (not distributed durability).
- CloudTrail analyzer rewritten with accurate fields/tests; K8s RBAC heuristic corrected; OAuth PKCE moved to `go test`.
- Unsafe duplicate Go demos and open-RDP Azure Firewall `main.tf` retired.
- Dual-palette × dual-viewport axe audit: **0 critical/serious, 0 moderate** locally after footer/button/scroll-region fixes.
- `npm run verify:all` entry point + `.github/workflows/gh-pages-quality.yml`.

## Executable validation (local, pre-CI)
| Suite | Result |
|-------|--------|
| AI broker | 12/12 including concurrent replay |
| OAuth/OIDC Node | **14**/14 |
| OAuth PKCE Go | `go test` pass |
| CloudTrail Go | `go test` / `go vet` pass |
| K8s RBAC Go | `go test` / `go vet` pass |
| Other JS labs | pass (secure-cicd, k8s model, supply-chain, iam-oidc, iac-policy) |
| Static site | pass |
| html-validate | 0 errors |
| Defect patterns | 21 patterns / 215 artifacts |
| axe (default+slate × desktop+mobile) | 0 critical/serious, 0 moderate |
| External links | 164 reachable, 1 limited (Uber newsroom 406) |
| Gitleaks 8.30.0 | no leaks |

## Known limitations
- Kyverno image policy: schema/offline only.
- Tetragon: schema only.
- Supply-chain: offline adapter only.
- AI ApprovalStore: teaching in-memory CAS.
- No cloud deployment during validation.
- Committed `qa/*.json` may lag HEAD after the report commit; CI artifacts are the bindable evidence.

## Workflow
See Actions run for `gh-pages quality` on this head. Required jobs: static-site, javascript-labs, go-utilities, policy-and-iac, postgresql-rls, accessibility, external-links, secret-scan, verify-evidence-reports, summary.

## Review state
**Draft** until the complete latest-head workflow is green.
