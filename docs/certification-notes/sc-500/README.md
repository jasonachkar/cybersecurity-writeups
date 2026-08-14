---
title: "Microsoft SC-500 study notes"
type: "certification-notes"
tags:
  - sc-500
  - microsoft-security
  - study-notes
date: "2026-07-25"
lastReviewed: "2026-07-25"
readingTime: 6
reviewStatus: "partially-verified"
validatedAgainst:
  - "Official Microsoft SC-500 study guide, updated 2026-05-13"
sourceQuality: "primary-sources-reviewed"
implementationStatus: "illustrative"
reviewIntervalDays: 90
---

# Microsoft SC-500 study notes

**Content type: Study Notes.** These notes support exam preparation; they are not equivalent to a tested implementation, customer deployment, or production security assessment.

Exam objectives change. Verify against the [current official Microsoft study guide](https://learn.microsoft.com/en-us/credentials/certifications/resources/study-guides/sc-500) before using this outline. The grouping below was checked on 2026-07-23 against the guide last updated by Microsoft on 2026-05-13. Percentages are intentionally omitted because they can change independently of this repository.

## Current skills groups

1. [Manage identity, access, and governance](domain-1-identity.md)
2. [Secure storage, databases, and networking](domain-2-storage-networking.md)
3. [Secure compute, including AI and agent workloads](domain-3-secure-compute.md)
4. [Manage and monitor security posture](domain-4-manage-monitor-posture.md)

AI security is part of **Secure compute** in the current outline; it is not a standalone fifth or unofficial domain. The group also includes servers and virtual machines, containers and AKS, application platform services, API Management, and web application firewall controls.

## Evidence boundary

These pages summarize product areas named by the exam owner. They do not demonstrate that a control was enabled in an Azure tenant. Product availability, licensing, preview/GA status, portal placement, and exam coverage can change. Use Microsoft Learn product documentation and a disposable authorized lab tenant for hands-on practice.

For threat-driven engineering coverage of model and tool authorization, see [AI Agent Security: External Authorization and Tool Trust Boundaries](../../../appsec/ai-agent-security.md) and its [runnable tool-broker lab](../../../labs/ai-agent-security/README.md).

## Study approach

- Map each objective to the control plane that enforces it.
- Distinguish configuration, runtime protection, posture findings, and monitoring.
- Practice least-privilege access, private networking, policy rollout, and evidence collection in an authorized lab.
- Record prerequisites, licensing, failure behavior, and rollback rather than memorizing portal paths.
- Re-check the official outline shortly before the exam.

## References

- [Official SC-500 study guide](https://learn.microsoft.com/en-us/credentials/certifications/resources/study-guides/sc-500)
- [Microsoft Defender for Cloud documentation](https://learn.microsoft.com/en-us/azure/defender-for-cloud/)
- [Microsoft Entra documentation](https://learn.microsoft.com/en-us/entra/)
- [Microsoft Sentinel documentation](https://learn.microsoft.com/en-us/azure/sentinel/)
