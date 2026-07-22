# Research and source policy

Security advice in this repository can influence production access, incident
response, architecture, and compliance decisions. This policy defines what counts
as adequate evidence and how uncertainty must be represented.

## Source hierarchy

Use the strongest source available for the claim:

1. Final standards and specifications from the owning standards body.
2. Current first-party product documentation and source repositories.
3. Incident-owner disclosures, court records, and regulator publications.
4. Reproducible tests in this repository.
5. High-quality secondary analysis that links to its primary evidence.

Do not use search snippets, unsourced social posts, copied configuration, or an
AI-generated answer as evidence. A secondary source may help find a primary source,
but it should not replace one when the primary source is available.

## Currency and versioning

- Record the exact specification or product version used for validation.
- State whether a document is final, draft, preview, proposed, deprecated, or a
  living publication.
- Use an absolute review date. Words such as "current" and "latest" are permitted
  only when the article also records what was checked and when.
- Preserve historical guidance only when it is useful for migrations or incident
  chronology. Mark it historical and identify the current replacement.
- Review time-sensitive control-plane, CI/CD, identity, and cryptography guidance at
  least every 180 days. Review slower-moving conceptual material at least annually.

The maintained status matrix is in
[`docs/standards/security-standards-review.md`](standards/security-standards-review.md).

## Claim classification

Use one of these labels when the context could be misunderstood:

| Label | Meaning |
| --- | --- |
| Confirmed fact | Directly supported by a cited primary source. |
| Reproduced result | Produced by a linked test with recorded prerequisites and versions. |
| Engineering judgment | A reasoned recommendation whose assumptions and trade-offs are stated. |
| Illustrative example | A teaching example; not a claim that the design is deployed. |
| Proposal | A future design or change that has not been implemented. |
| Requires author confirmation | Project-specific history that cannot be verified from repository evidence. |

## Incident research

For breach chronology, separate these questions:

- What did the affected organization or a competent authority confirm?
- When did access occur, when was it detected, and when was it disclosed?
- Which control existed at the time? A control released later is a retrospective
  defense-in-depth recommendation, not a contemporaneous missed control.
- Which causal statements are confirmed, and which are inferences?

Avoid sensational scope language. Report affected records, systems, or credentials
only at the precision supported by the source.

## Code validation

Every executable example carries an implementation status:

- `tested`: an automated, linked test exercises the important success and failure
  paths in a declared environment.
- `partially-tested`: syntax or selected behavior is automated; state the gaps.
- `illustrative`: plausible example not exercised here.
- `pseudocode`: intentionally incomplete and not directly executable.

Passing syntax validation does not prove a secure design. Security boundaries need
negative tests, including absent context, malformed context, cross-tenant access,
privilege bypass, untrusted artifacts, or verification failure as applicable.

## Citation format

Use descriptive Markdown links to canonical HTTPS pages. Prefer a citation next to
the claim. Finish substantive articles with a `## References` section that includes
the standards and product documentation used in the review. Do not list sources that
were not actually used.

## Handling unavailable evidence

If evidence cannot be obtained, do not fill the gap with a confident claim. Mark the
field `requires-review`, describe the missing evidence, and add a concrete review
action. Drafts may be discussed when useful, but must never be presented as final.
