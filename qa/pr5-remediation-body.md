# PR #5 — final remediation evidence (source for PR body)

Branch: `codex/validated-gh-pages-deployment`  
Target: `gh-pages`  
Do not merge from this note alone — wait for green branch-head and merge-ref CI.

## Summary

- Runtime QA JSON reports are no longer git-tracked; GitHub Actions artifacts are authoritative.
- `npm run verify:all` orchestrates static, Node labs, Go, Terraform 1.14.6, OPA 1.17.0, Bicep, policy schemas, Kyverno 1.18.2 native hardened-pod tests, PostgreSQL RLS, ShellCheck, PowerShell parse, a11y, links, and Gitleaks (working tree + history).
- Artifact uploads are explicit per job; assembly fails on missing or duplicate basenames.
- Public provenance uses timeless publication wording (target `gh-pages`, review PR #5).
- `404.html` is a `site-utility` missing-page experience (not archived guidance).
- AI action bindings use SHA-256 of canonical JSON; K8s RBAC auditor uses RoleKey identity and binding semantics.

## Remaining limitations

- No live Kyverno signature admission
- No live Tetragon enforcement
- No production DSSE verification
- In-memory AI approval store
- No cloud deployment
- Some external sites may block automated link checking
- PowerShell suite is syntax-parse only
