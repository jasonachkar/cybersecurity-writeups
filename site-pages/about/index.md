# About this site

I'm Jason Achkar Diab. This repository contains my cybersecurity research, labs,
scripts, and study notes across cloud security, application security, DevSecOps,
and threat intelligence.

## How it is organized

- **Research** documents a security decision or architecture question and states
  what was tested versus what remains conceptual.
- **Labs** exercise bounded decisions locally with positive and negative fixtures.
- **Scripts** are small tools or packages developed alongside the research.
- **Study notes** summarize official certification material; they are not
  implementation evidence.

## How it is maintained

### Research methodology

Markdown, metadata, examples, and the documentation build are validated on
`main`. The staged site includes a source-and-artifact manifest, and publication
is blocked whenever canonical routes or lifecycle classifications drift.

The evidence rows on research pages distinguish repository-tested examples from
illustrative architecture, record the article's review state, and describe the
quality of sources used for consequential claims. A current review date is not
itself proof that the guidance is correct: material remains marked
`requires-review` until it has been checked against its declared
`validatedAgainst` sources.

Passing repository checks means the documented local tests behaved as expected.
It does not claim that every design was deployed to a live environment.

## Source

The source for this site is public in the
[cybersecurity-writeups repository](https://github.com/jasonachkar/cybersecurity-writeups).
