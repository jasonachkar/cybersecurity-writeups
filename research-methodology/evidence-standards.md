# Evidence standards

This is the portfolio's proposed review contract. It describes how to assess the
work here; it is not an industry certification or a claim of independent review.

## Evidence tiers

| Tier | Evidence | What it cannot establish |
| --- | --- | --- |
| T0 | Assertion, documented capability, or engineering guidance; cite the primary source | Local configuration or behavior |
| T1 | Versioned configuration, compiled template, static policy/schema result | Enforcement, reachability, or successful authentication |
| T2 | Observed allowed behavior with exact input, output, version, and command | Rejection of hostile inputs |
| T3 | Negative/adversarial cases against an owned isolated target, with state assertions | Untested bypass resistance or production effectiveness |
| T4 | Matched vulnerable/remediated comparison over the same cases and initial state | General superiority outside the tested conditions |

Every major claim must identify its tier, artifact, and scope, either inline or in
a claim ledger. Tiers describe evidence strength for that claim, not article rank.
A compiled deny policy remains T1 until behavior is exercised. A local interpreter's
T3 result is evidence about that interpreter, not about AWS, Azure, or a cluster.

## Uncertainty language

| Label | Use |
| --- | --- |
| Observed | Directly produced by the linked lab; give the case and result |
| Likely | An inference from stated evidence; describe the missing experiment |
| Assumed | A prerequisite not established here, such as independent log ownership |
| Not established | Evidence is insufficient; do not imply successful exploitation |
| Not tested | The method was not executed in the declared environment |

Separate sourced product behavior (T0 in this portfolio) from locally reproduced
behavior. A vendor document can be authoritative without being a local experiment.
Never promote a boolean verifier fixture to a cryptographic-verification result.
Maintain `requires-review` until an evidence reviewer completes the source check.

## Required artifacts by research type

| Type | Minimum review artifacts |
| --- | --- |
| Cloud | Terraform/provider locks, scope diagram, privilege assumptions, plan/validation, allowed/denied API matrix, audit event, teardown and cost model; mark cloud execution absent when absent |
| Application | Seed state, auth/session contract, endpoint × actor × object matrix, requests/responses, before/after state assertions, denied-attempt logs |
| AI agent | Principal/delegation map, untrusted-input entry, tool schema/authorization, denied tool invocation, egress decisions, bounded evidence retention; distinguish simulated tool calls from a real model run |
| Detection | Synthetic fixtures with labels, parser/query, true/false positive and negative counts, missing-source case, event/ingestion/alert clocks, deduplication and response limits |
| Supply chain | Artifact digest, provenance, expected identity/source/builder, trusted verifier boundary, tamper cases, missing/failed evidence and promotion decision |

Do not collect live credentials as evidence. Use generated local sessions, synthetic
records and mock metadata. Redact authorization headers, cookies, URL queries and
bodies before persistence. Keep only fields needed to reproduce a decision.

## Measurement contract

Declare the corpus, denominator, seed/reset strategy, repetitions, and exclusions.
Publish machine-readable case results; a failing security assertion returns nonzero.
Distinguish a test failing from an attack being correctly denied.

| Outcome | Measurement |
| --- | --- |
| Coverage | Exercised threat cases / enumerated threat cases; list omissions |
| False positives | Benign cases denied / benign cases exercised |
| False negatives | Hostile cases allowed / hostile cases exercised |
| Time to detect | Alert creation minus event occurrence, with clock and ingestion uncertainty |
| Time to contain | Independently verified access loss minus containment decision; distinguish token expiry from revocation |
| Pipeline impact | Repeated elapsed times with/without gate on the same runner and inputs; report sample size |
| Operational cost | CPU, memory, requests, storage/retention, operator effort and cloud rates; do not infer a monthly bill from static code |
| Residual risk | Remaining actor capability after each control fails; include ownership and recovery boundary |

When clocks, live integrations, billing, or representative workloads are absent,
write **not measured in this lab** and specify the future experiment. Fixture
accuracy is not a population estimate of detection effectiveness.

## Review and references

Save a source-to-claim mapping, source version/status and access date. Consult final
standards, product documentation, source and incident-owner disclosures directly.
Living documents are dated observations. Keep drafts and historical advice labeled.
Use the repository [research policy](https://github.com/jasonachkar/cybersecurity-writeups/blob/main/docs/RESEARCH_POLICY.md) and
[metadata contract](https://github.com/jasonachkar/cybersecurity-writeups/blob/main/docs/METADATA.md) for publication and lifecycle review.

## References

- [Repository research policy](https://github.com/jasonachkar/cybersecurity-writeups/blob/main/docs/RESEARCH_POLICY.md)
- [Security article metadata contract](https://github.com/jasonachkar/cybersecurity-writeups/blob/main/docs/METADATA.md)
