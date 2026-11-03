# Research methodology

This site treats security research as an evidence-producing discipline. Its labs
use owned local targets; architecture guidance is not production-test evidence.

## Research, documentation, and tutorials

**Research** asks a falsifiable question and produces evidence that could disprove
its hypothesis. **Documentation** explains a sourced capability or design.
**A lab tutorial** makes a procedure repeatable. A page can combine these forms,
but must identify which conclusions come from experiments and which are proposals.

## Research model

Each deep-dive follows: Question, Hypothesis, Threat model, Method, Evidence, Findings, Practical guidance, Limitations, and Open questions.

Start with an actor, asset and disputed boundary. Define the success and failure
conditions before implementing a fix. Run the same cases against vulnerable and
remediated paths, reset state between cases, and test allowed behavior as well as
denials. Preserve useful historical explanation with an explicit historical label.

## Article contract

| Section | Review question |
| --- | --- |
| Question | Which decision is this investigation intended to inform? |
| Hypothesis | What observable result would refute the proposed control? |
| Threat model | What can the actor control, and what remains trusted? |
| Method | Which commands, versions, fixtures and state resets reproduce the test? |
| Evidence | Which input, output, log and state assertion support each claim? |
| Findings | What was observed, separately from interpretation? |
| Practical guidance | Which boundary should enforce the decision, and who operates it? |
| Limitations | What was not tested, and where does the claim stop? |
| Open questions | Which next experiment could change the conclusion? |

Every major claim carries a T0–T4 tier using the
[evidence standards](evidence-standards.md). Every research article states what was
not tested. A link to a lab does not imply that the full architecture was exercised.

## Start here

- [Research index and evidence coverage](research-index.md)
- [Specific open research questions](open-questions.md)
- [Vulnerability research and paired experiments](../vulnerability-research/index.md)
- [Reusable article template](https://github.com/jasonachkar/cybersecurity-writeups/blob/main/docs/templates/security-writeup-template.md)

## Publication boundary

Source changes go on `research-depth-upgrade`, reviewed through a PR into `main`.
The content-quality workflow builds MkDocs and publishes the exact verified static
artifact to `gh-pages` only after a push to `main`. GitHub Pages serves `gh-pages`
at its root with the existing custom domain. Do not edit generated HTML there.
See the [deployment review](../publishing/deployment-review.md).

## References

- [Repository source policy](https://github.com/jasonachkar/cybersecurity-writeups/blob/main/docs/RESEARCH_POLICY.md)
- [Canonical documentation pipeline](https://github.com/jasonachkar/cybersecurity-writeups/blob/main/tools/docs-pipeline/README.md)
