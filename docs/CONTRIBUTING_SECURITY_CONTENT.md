# Contributing security content

Security guidance in this repository is reviewed as an engineering artifact. A
submission should make it possible to identify the trust boundary, enforcement point,
evidence, failure behavior, and residual risk behind a recommendation.

## Required article structure

Use the sections that apply to the subject; explain an omission when it would be
surprising:

1. Executive summary
2. Scope and non-goals
3. System assumptions
4. Threat model and trust boundaries
5. Attack preconditions and attack path
6. Defensive architecture
7. Enforcement points
8. Implementation
9. Verification and expected results
10. Negative tests
11. Operational considerations
12. Failure modes and bypasses
13. Residual risk
14. Version compatibility
15. References
16. Last technically reviewed date

Start new articles from
[`docs/templates/security-writeup-template.md`](templates/security-writeup-template.md)
and follow the [metadata contract](METADATA.md).

## Evidence labels

Every executable or configuration example must be labeled:

- `tested`: executed by repository automation with positive and negative cases;
- `partially-tested`: a bounded subset is automated and the gap is stated;
- `illustrative`: syntax or architecture guidance that is not claimed deployable; or
- `pseudocode`: intentionally incomplete logic used to explain a decision.

Do not use `production-ready` unless the artifact documents supported versions,
automated positive and negative validation, observability, rollback, failure
behavior, assumptions, and operational limitations. Passing schema validation alone
does not qualify.

## Claim review

Prefer bounded language:

> This control reduces the demonstrated attack path under the following assumptions.

> The policy was validated against the pinned CLI using these positive and negative
> fixtures.

> This design does not protect against the following conditions.

Avoid universal language unless a cited specification defines the property and the
implementation test exercises it. Run:

```text
node scripts/validate-claims.js --write
node scripts/validate-claims.js --check
```

The generated queue is a triage tool, not an automatic fact checker. If a strong
claim is intentionally retained, add an adjacent suppression with a concrete reason:

```text
<!-- claim-reviewed: RFC 9700 section X defines this protocol requirement. -->
```

Generic justifications are rejected.

## Sources

Use primary sources for protocol, platform, standard, framework, and configuration
semantics:

- RFC Editor and named standards bodies;
- official cloud, Kubernetes, PostgreSQL, Terraform/OpenTofu, OPA, Kyverno, Sigstore,
  SLSA, and GitHub documentation;
- project source repositories and versioned release notes; and
- incident-owner disclosures, legal filings, and regulator reports for incidents.

Secondary sources may add practitioner context but must not replace an available
primary source. Distinguish confirmed facts, documented inference, and unknowns.
Place citations close to consequential claims.

## Security-control operations

For blocking controls, address:

- owner and deployment stage;
- observe, audit, warn, and enforce rollout;
- exception approval and expiry;
- break-glass authority;
- alerting and control-health telemetry;
- false positives and developer experience;
- rollback and incident response;
- latency, cost, maintenance, and deprecation risk; and
- residual risk and bypass measurement.

Recommended rollout language is:

```text
observe → audit → warn → enforce → measure bypasses
```

## Validation before review

Run the repository gate:

```text
npm ci --ignore-scripts
npm run validate
```

When a locally optional native tool is unavailable, report the limitation. CI
requires the pinned native policy tools and must not replace a failure with a
structural-only pass. Validation must not deploy cloud resources or use live secrets.

## Pull-request evidence

The pull-request description should list:

- claims or behavior changed;
- exact files and evidence paths;
- positive and negative fixtures;
- tested tool versions and commands;
- observed results;
- limitations and follow-up work; and
- deployment impact.

Do not claim that the public site changed until the deployment workflow and public
`site-meta.json` confirm the source commit.
