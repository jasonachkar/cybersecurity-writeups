---
id: api-bola-multi-tenant
title: Multi-tenant API authorization comparison lab
navTitle: Multi-tenant BOLA
domain: appsec
order: 110
summary: Reproduce the owned Multi-tenant BOLA experiment and inspect its implementation and evidence limits.
implementationStatus: partially-tested
related:
  research: [api-bola-multi-tenant]
sourceFiles:
  - { path: vulnerability-research/api-bola-multi-tenant/lab/api.py, label: Implementation, language: python, primary: true }
runCommands: ["python3 vulnerability-research/api-bola-multi-tenant/lab/test_api.py"]
---

# Multi-tenant API authorization comparison lab

The [canonical setup and teardown](../../vulnerability-research/api-bola-multi-tenant/lab/README.md)
contains prerequisites, isolation, complete code, commands, expected output and
evidence collection. The [research study](../../vulnerability-research/api-bola-multi-tenant/index.md)
contains the threat model, comparison matrix, limitations and consulted sources.

Run from repository root after reading that setup:

```sh
python3 vulnerability-research/api-bola-multi-tenant/lab/test_api.py
```

These are owned teaching targets. Cloud deployment is excluded. See the study's
claim ledger before treating local model output as product enforcement evidence.

## References

- [Research and evidence](../../vulnerability-research/api-bola-multi-tenant/index.md)

## Related maintained investigations

- [api microservices threat modeling](../../appsec/api-microservices-threat-modeling.md)
