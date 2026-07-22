# Repository instructions for security content

These instructions apply to every directory in this repository.

## Evidence and claims

- Treat security guidance as an engineering artifact, not opinion copy.
- Prefer primary sources: standards bodies, vendor documentation, incident-owner
  disclosures, court records, and source repositories.
- Never silently convert an assumption, design proposal, illustrative example, or
  unverified incident detail into a fact.
- Distinguish final standards from drafts, previews, proposals, and living catalogs.
- Put a `References` section in substantive articles and place citations next to
  consequential claims when the source-to-claim mapping would otherwise be unclear.
- Do not invent client names, production results, penetration-test findings,
  implementation history, or quantitative outcomes.

## Code and configuration

- Label examples as `tested`, `partially tested`, `illustrative`, or `pseudocode`.
- Link tested examples to a runnable lab or automated validation.
- Pin third-party GitHub Actions to a full commit SHA and retain a comment naming the
  reviewed release.
- Use least privilege, deny-by-default behavior, explicit failure semantics, and
  negative tests for security boundaries.
- Never add live credentials or credential-shaped examples. Use unmistakable
  placeholders such as `<tenant-id>`.

## Metadata and lifecycle

- Follow `docs/METADATA.md` for indexed security articles.
- A current review date is not proof of correctness. Use `requires-review` until a
  reviewer has checked the material against the sources in `validatedAgainst`.
- Update `lastReviewed`, `reviewStatus`, `sourceQuality`, and
  `implementationStatus` together when evidence changes.
- Run `npm run validate` before proposing a merge. If an optional external tool is
  unavailable, record that limitation instead of claiming its checks passed.

## Editing discipline

- Preserve useful historical explanation, but label it historical and add the
  current replacement.
- Prefer focused, reviewable commits: audit/governance, factual corrections,
  flagship engineering content, labs, and automation.
- Do not deploy cloud resources from repository validation. Cloud examples stop at
  compilation, policy evaluation, or a documented plan/what-if command unless a
  human explicitly authorizes deployment.
