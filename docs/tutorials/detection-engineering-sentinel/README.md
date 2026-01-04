---
title: "Detection Engineering with Microsoft Sentinel"
type: tutorial
tags: [SIEM, Detection Engineering, Microsoft Sentinel, KQL, Cloud Security]
date: 2024-09
readingTime: 14
---

# Detection Engineering with Microsoft Sentinel

## Introduction

Security monitoring is often misunderstood as deploying dashboards and enabling log collection. In reality, effective security monitoring depends on **high-quality detections** that identify malicious behavior early while minimizing false positives.

This write-up documents a practical introduction to **detection engineering using Microsoft Sentinel**, with a focus on crafting meaningful KQL-based detections for identity abuse, lateral movement, and privilege escalation in Azure environments.

The emphasis is on **behavioral detection**, not alert spam.

---

## What Is Detection Engineering?

Detection engineering is the discipline of designing, implementing, and maintaining detection logic that identifies security threats based on attacker behavior rather than static indicators.

Unlike traditional rule-based monitoring, detection engineering focuses on:
- Abnormal patterns
- Contextual signals
- Correlation across data sources
- Continuous tuning and improvement

---

## Detection Engineering vs Logging

Logging answers the question:
> *“What happened?”*

Detection engineering answers:
> *“Is this suspicious or malicious?”*

Without detection logic, logs provide visibility but no protection.

---

## Microsoft Sentinel Overview

Microsoft Sentinel is a cloud-native SIEM and SOAR platform that provides:
- Centralized log ingestion
- Advanced analytics using KQL
- Alerting and incident management
- Automated response playbooks

Sentinel is most effective when detections are **custom-built** for the environment, rather than relying solely on default rules.

---

## Data Sources Used

Effective detections depend on high-quality telemetry. The following data sources were used:

- Azure Entra ID sign-in logs
- Azure Entra ID audit logs
- Azure Activity Logs
- Azure Firewall / Network Security logs
- Microsoft Defender signals (when available)

Detection quality is directly proportional to telemetry quality.

---

## Detection Design Principles

Before writing queries, several principles were established:

### Detect Behavior, Not Tools

Attackers change tools frequently. Behavior such as unusual login patterns or privilege changes is harder to evade.

### Minimize False Positives

An alert that fires constantly will eventually be ignored. Precision is more valuable than volume.

### Include Context

Alerts should provide enough information to support triage without requiring manual log hunting.

---

## Detection Scenario 1: Suspicious Authentication Patterns

### Threat Description

Attackers often attempt to authenticate from:
- Unusual geolocations
- Multiple locations in a short timeframe
- Anonymous or risky IP addresses

### Detection Logic

This detection identifies authentication attempts from multiple countries within a short time window.

### Example KQL

```kql
SigninLogs
| where ResultType == 0
| summarize Countries = dcount(LocationDetails.countryOrRegion)
          by UserPrincipalName, bin(TimeGenerated, 1h)
| where Countries > 1
```

### Why This Works

Legitimate users rarely authenticate successfully from multiple countries within an hour. This behavior is often associated with compromised credentials.

---

## Detection Scenario 2: Impossible Travel

### Threat Description

Impossible travel occurs when authentication events are geographically impossible given the time between logins.

### Detection Logic

This detection correlates successful sign-ins and evaluates geographic distance versus time.

### Mitigation Considerations

* Exclude known VPN ranges
* Tune thresholds to reduce false positives
* Correlate with device and risk signals

---

## Detection Scenario 3: Privilege Escalation Events

### Threat Description

Privilege escalation is a critical step in most cloud attacks.

### Detection Targets

* Role assignments
* PIM activations
* Changes to directory roles

### Example KQL

```kql
AuditLogs
| where OperationName contains "Add member to role"
| project TimeGenerated, InitiatedBy, TargetResources
```

### Why This Matters

Many breaches escalate privileges shortly after initial access. Detecting these events early can prevent further damage.

---

## Detection Scenario 4: Lateral Movement Indicators

### Threat Description

After gaining access, attackers attempt to move laterally to access additional resources.

### Detection Signals

* Access to multiple resources in rapid succession
* Unusual API access patterns
* Cross-subscription access anomalies

### Key Insight

Lateral movement often appears as **legitimate activity**, making contextual correlation essential.

---

## Detection Scenario 5: Token Abuse

### Threat Description

OAuth tokens may be stolen and reused from unexpected locations or devices.

### Detection Signals

* Token usage without corresponding interactive sign-in
* Token usage from unfamiliar IP ranges
* High-frequency API calls

### Mitigations

* Short token lifetimes
* Conditional Access enforcement
* Token binding where supported

---

## Alert Enrichment and Context

A detection is only useful if analysts can act on it quickly.

Each alert should include:

* User and tenant context
* Source IP and location
* Related events
* Severity and confidence level

This reduces mean time to triage (MTTT).

---

## Alert Tuning and Maintenance

Detection engineering is an iterative process.

### Common Tuning Activities

* Adjust thresholds
* Add exclusions for known-good behavior
* Correlate additional data sources
* Retire low-value detections

Untuned detections create alert fatigue.

---

## Measuring Detection Effectiveness

Key metrics:

* False positive rate
* Mean time to detect (MTTD)
* Mean time to respond (MTTR)
* Analyst feedback

Detections should evolve with the environment.

---

## Common Mistakes

* Relying only on built-in analytics rules
* Writing overly broad queries
* Ignoring alert quality
* Treating detection engineering as a one-time task

---

## Key Lessons Learned

* High-signal detections outperform noisy dashboards
* Context is as important as the detection itself
* Identity-based detections are critical in cloud environments
* Continuous tuning is required to maintain effectiveness

---

## Conclusion

Detection engineering transforms raw telemetry into actionable security intelligence. By focusing on attacker behavior, contextual correlation, and continuous improvement, Microsoft Sentinel can be used to detect real threats rather than generating noise.

This project strengthened my understanding of cloud-native SIEM operations, identity-focused threat detection, and the practical realities of operating security monitoring at scale.

---

## References

* Microsoft Sentinel Documentation
* MITRE ATT&CK Framework
* NIST SP 800-92 (Logging and Monitoring)
