# Security write-up authoring guide

## Start with a decision

A senior engineering article should help a reader make or review a decision. Define
the scope, non-goals, assets, trust boundaries, threat actors, and assumptions before
listing controls. State viable alternatives and why they were not selected.

For implementation-oriented work, include:

- threat model and abuse cases;
- control mapping and residual risk;
- failure modes and safe failure behavior;
- deployment, rollback, and operational ownership;
- observability signals and incident hooks;
- cost and usability trade-offs;
- validation evidence, including negative tests;
- explicit limitations and unknowns.

Use [the security write-up template](templates/security-writeup-template.md) for new
material. Concise articles may combine sections, but should not omit the underlying
reasoning.

For a new primary research article, use the canonical scaffold instead of copying
frontmatter from an existing page:

```bash
npm run research:new -- \
  --domain appsec \
  --slug secure-token-exchange \
  --title "Secure Token Exchange"
```

The command validates the domain and slug, rejects collisions, selects the next
domain order, and creates conservative `requires-review` metadata. It prints the
canonical path plus preview and verification commands. Keep the generated stable
`id` when renaming the article. Omit `readingTime` unless the derived estimate has a
documented reason to be overridden.

## Write claims that can survive review

Apply the [research policy](RESEARCH_POLICY.md). Cite primary sources close to
consequential claims. Say "the vendor documents" for a sourced capability and
"recommended here" for engineering judgment. Do not turn a lab result into a
production guarantee.

Use exact dates in incident timelines. If a mitigation was released after an
incident, label it retrospective. When documentation is versioned, include the
version or the date reviewed.

## Build examples as small systems

Runnable examples need prerequisites, setup, expected output, cleanup, versions,
limitations, and negative tests. Use deterministic fixtures and fail closed on an
invalid or missing security signal. Link the article to the lab and the lab back to
the article.

For CI/CD examples:

- minimize token permissions;
- treat pull-request content, issue fields, artifacts, caches, and generated output
  as untrusted;
- avoid interpolating untrusted expressions into shell source;
- pin third-party actions to full commit SHAs;
- keep build and privileged release identities separate;
- verify provenance against artifact digest, expected issuer, builder, source, and
  policy.

## Local review

From the repository root:

```powershell
npm ci
npm run docs:serve
npm run verify:all
```

Use `npm run verify:docs` for the documentation-product checks alone and
`npm run links:external` when intentionally checking external destinations.

Run lab-specific commands documented in each lab. Cloud validation stops before
deployment unless the task explicitly authorizes a target subscription/account and
a human reviews the plan or what-if result.

Before committing, inspect `git diff --check`, regenerated indexes, validation
output, and any remaining `requires-review` entries affected by the change.
