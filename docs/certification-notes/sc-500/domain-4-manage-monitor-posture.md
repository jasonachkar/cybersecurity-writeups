---
title: "Study Notes: Manage and monitor security posture"
type: "certification-notes"
tags:
  - sc-500
  - defender-for-cloud
  - microsoft-sentinel
date: "2026-07-25"
lastReviewed: "2026-07-25"
readingTime: 7
reviewStatus: "partially-verified"
validatedAgainst:
  - "Official Microsoft SC-500 study guide, updated 2026-05-13"
sourceQuality: "primary-sources-reviewed"
implementationStatus: "illustrative"
reviewIntervalDays: 90
---

# Study Notes: Manage and monitor security posture

<div class="aside study-currency" aria-label="Official-owner check">

**Official-owner check**

Microsoft study guide last updated **2026-05-13**. The maintained collection follows the current four domains. [Official SC-500 study guide](https://learn.microsoft.com/en-us/credentials/certifications/resources/study-guides/sc-500).

</div>

The current fourth skills group covers Defender for Cloud posture and workload protection, Microsoft Sentinel collection and automation, and Microsoft Security Copilot administration.

## Defender for Cloud

Study:

- Defender CSPM risk discovery and attack-path context;
- regulatory-compliance assessment;
- workload protection plan configuration;
- AWS and Google Cloud connectors;
- Defender Vulnerability Management settings for Azure VMs; and
- External Attack Surface Management discovery.

A recommendation is not evidence that remediation occurred. Review the affected resource, exemption, owner, due date, control health, and the telemetry that confirms the intended state.

## Microsoft Sentinel

Study:

- workspaces and role assignments;
- Content Hub solutions and Microsoft data connectors;
- syslog, CEF, Windows Security Events, WEF, and data collection rules;
- custom log tables, retention, and query cost;
- automation rules and playbooks; and
- Microsoft Purview Audit queries in Defender XDR.

Collection design must account for source authentication, parsing, delay, loss, retention, sensitive fields, and a health alert when an expected source stops reporting.

## Microsoft Security Copilot

Study workspace configuration, roles and permissions, plugins, and Microsoft or Security Store agents. Treat plugin and agent permissions as capability grants. Model-generated text does not grant authority to query a tenant, invoke a tool, or change a security control.

## Operational review

For each posture or monitoring control, identify:

- owner and required license;
- audit versus enforcement behavior;
- exception and break-glass path;
- data source, delay, retention, and failure alert;
- automation identity and approval boundary; and
- rollback and incident-response evidence.

## References

- [Official SC-500 study guide](https://learn.microsoft.com/en-us/credentials/certifications/resources/study-guides/sc-500)
- [Microsoft Defender for Cloud](https://learn.microsoft.com/en-us/azure/defender-for-cloud/)
- [Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/)
- [Microsoft Security Copilot](https://learn.microsoft.com/en-us/copilot/security/)
