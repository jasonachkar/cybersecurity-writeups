# Validated gh-pages remediation — PR #5

## Scope
Only `codex/validated-gh-pages-deployment` → `gh-pages`. **No deployment occurred during validation.**

## Exact head (green CI)
- **gitCommit:** `7d53aa7d81a0709d766211fe78c8891d01d52b5a`
- **gitTree:** `5ed660a5e0f7f93a52dae25d8f72cb44a7e96263`
- **Workflow:** https://github.com/jasonachkar/cybersecurity-writeups/actions/runs/30097733952 (`conclusion: success`, `2026-07-24T13:41:18Z`)

## Required checks (all SUCCESS)
static-site · javascript-labs · go-utilities · policy-and-iac · postgresql-rls · accessibility · external-links · secret-scan · verify-evidence-reports · summary

## Remediation highlights
- **AI broker:** atomic `ApprovalStore.consumeIfUnused`; concurrent replay → one executor invocation; docs bound to in-memory teaching CAS.
- **Legacy utilities:** CloudTrail + K8s RBAC rewritten with tests; OAuth PKCE → `go test`; JWT/IDOR/IAM/SCP/pipeline/SBOM/secret demos and open-RDP Azure Firewall `main.tf` **retired**.
- **A11y:** default+slate × desktop+mobile; local audit 0 critical/serious and 0 moderate after footer/button/scroll-region fixes.
- **QA:** commit/tree-stamped reports; `npm run verify:all`; CI regenerates authoritative artifacts.
- **OAuth Node lab:** **14**/14 cases (not 9).

## Known limitations (intentional)
- Kyverno image policy: schema/offline only (not live signature admission).
- Tetragon: schema only (no live cluster enforcement).
- Supply-chain: offline adapter contract only.
- AI ApprovalStore: not distributed durable storage.
- Uber newsroom link may remain bot-blocked (limited, not broken).
- No cloud resources deployed.

## Review state
PR remains **draft**. Latest-head workflow is green and ready for **independent final review** (not merge from this agent).
