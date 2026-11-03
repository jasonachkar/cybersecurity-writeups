---
id: cicd-identity-escalation
title: CI/CD identity escalation policy lab
navTitle: CI/CD identity escalation
domain: devsecops
order: 120
summary: Reproduce the owned CI/CD identity escalation experiment and inspect its implementation and evidence limits.
implementationStatus: partially-tested
related:
  research: [cicd-identity-escalation]
sourceFiles:
  - { path: vulnerability-research/cicd-identity-escalation/lab/main.tf, label: Implementation, language: terraform, primary: true }
runCommands: ["bash vulnerability-research/cicd-identity-escalation/lab/validate.sh"]
---

# CI/CD identity escalation policy lab

The [canonical setup and teardown](../../vulnerability-research/cicd-identity-escalation/lab/README.md)
contains prerequisites, isolation, complete code, commands, expected output and
evidence collection. The [research study](../../vulnerability-research/cicd-identity-escalation/index.md)
contains the threat model, comparison matrix, limitations and consulted sources.

Run from repository root after reading that setup:

```sh
bash vulnerability-research/cicd-identity-escalation/lab/validate.sh
```

These are owned teaching targets. Cloud deployment is excluded. See the study's
claim ledger before treating local model output as product enforcement evidence.

## References

- [Research and evidence](../../vulnerability-research/cicd-identity-escalation/index.md)

## Related maintained investigations

- [cloud detection and response](../../cloud-security/cloud-detection-and-response.md)
- [attack path analysis](../../threat-intel/attack-path-analysis.md)
