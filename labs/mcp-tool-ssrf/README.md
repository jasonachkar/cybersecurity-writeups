---
id: mcp-tool-ssrf
title: MCP-style SSRF comparison lab
navTitle: MCP-style SSRF
domain: ai-security
order: 100
summary: Reproduce the owned MCP-style SSRF experiment and inspect its implementation and evidence limits.
implementationStatus: partially-tested
related:
  research: [mcp-tool-ssrf]
sourceFiles:
  - { path: vulnerability-research/mcp-tool-ssrf/lab/fetcher.py, label: Implementation, language: python, primary: true }
runCommands: ["python3 vulnerability-research/mcp-tool-ssrf/lab/test_fetcher.py"]
---

# MCP-style SSRF comparison lab

The [canonical setup and teardown](../../vulnerability-research/mcp-tool-ssrf/lab/README.md)
contains prerequisites, isolation, complete code, commands, expected output and
evidence collection. The [research study](../../vulnerability-research/mcp-tool-ssrf/index.md)
contains the threat model, comparison matrix, limitations and consulted sources.

Run from repository root after reading that setup:

```sh
python3 vulnerability-research/mcp-tool-ssrf/lab/test_fetcher.py
```

These are owned teaching targets. Cloud deployment is excluded. See the study's
claim ledger before treating local model output as product enforcement evidence.

## References

- [Research and evidence](../../vulnerability-research/mcp-tool-ssrf/index.md)

## Related maintained investigations

- [cloud network segmentation](../../cloud-security/cloud-network-segmentation.md)
- [runtime protection rasp waf](../../appsec/runtime-protection-rasp-waf.md)
- [cloud breach case studies](../../threat-intel/cloud-breach-case-studies.md)
