---
title: "Cloud Detection Engineering: Durable Telemetry, High-Signal Analytics and Safe Response"
id: "cloud-detection-and-response"
navTitle: "Detection and response"
order: 50
type: "cloud-security"
tags:
  - cloud-security
  - cloud
  - detection
  - and
  - response
date: "2026-07-25"
lastReviewed: "2026-07-25"
reviewStatus: "partially-verified"
validatedAgainst:
  - "Microsoft Azure Monitor `AWSCloudTrail` table schema — https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/awscloudtrail"
  - "Microsoft `AWSCloudTrail` sample queries — https://learn.microsoft.com/en-us/azure/azure-monitor/reference/queries/awscloudtrail"
  - "AWS CloudTrail operation and trail delivery — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/how-cloudtrail-works.html"
  - "AWS CloudTrail organization-trail delivery troubleshooting — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-troubleshooting.html"
  - "AWS CloudTrail data-event selectors — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html"
  - "Amazon S3 Object Lock behavior and retention modes — https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html"
sourceQuality: "primary-sources-reviewed"
implementationStatus: "illustrative"
reviewIntervalDays: 90
---

# Cloud Detection Engineering: Durable Telemetry, High-Signal Analytics and Safe Response

Detection engineering is a chain of independently failing systems. A configured trail does not prove delivery; retained objects do not prove analytics ingestion; an alert does not prove routing; and an automation identity does not make containment safe.

## The core decision

Build two evidence paths: a retention-controlled archive for investigation and an operational analytics path for timely detection. Administer them independently where the threat model requires it, monitor each transition, and retain enough identifiers to reconcile missing or transformed events. Treat automated containment as a production control with bounded authority, idempotency, canaries, evidence preservation, rollback, and a tested break-glass path.

## Scope and trust boundaries

This reference uses AWS CloudTrail as an event source and Microsoft Sentinel's `AWSCloudTrail` table as an analytics destination. The principles apply to other cloud/SIEM combinations, but schemas and delivery guarantees must be revalidated.

| Stage | Owner and trust boundary | Evidence of health |
|----|----|----|
| Event generation | Cloud control plane and configured event coverage | Expected management/data/network activity events and selector configuration |
| Delivery | Trail, destination policy, encryption key, service role | Delivery status, latency, errors, object arrival, digest status where used |
| Archive retention | Write-restricted, independently administered storage | Versioning, retention mode, policy changes, inventory and read tests |
| Analytics ingestion | Connector, parser, workspace and ingestion permissions | Connector health, row freshness, volume and schema-drift checks |
| Detection execution | Rule scheduler and detection content | Rule enabled state, last run, synthetic/canary result, errors |
| Alert routing | Incident queue, paging and ownership | Delivery acknowledgement and escalation timer |
| Response authority | Automation identity and approval policy | Scoped permissions, execution audit, action result and rollback result |

## Durable telemetry pipeline

    AWS event source
      → CloudTrail selector and trail / event data store
      → delivery status and independently monitored destination
      → retention-controlled archive
      → SIEM connector and parser
      → schema/freshness/volume health
      → analytic rule
      → alert routing
      → human decision or bounded automation

Use precise storage terms. S3 Object Lock can prevent a protected object version from being overwritten or deleted for a retention period, depending on governance or compliance mode. It does not make the logging architecture “tamper-proof.” It does not ensure the event was generated, selected, delivered, readable after KMS changes, ingested, detected, or routed. Governance retention can be bypassed by specifically authorized principals, and Object Lock does not protect against loss of an encryption key.

A stronger design makes the archive retention-locked, write-restricted, separately administered, and monitored. Protect CloudTrail configuration, destination policies, KMS keys, SIEM connectors, analytics, response code, and the identities that administer each layer.

## Failure model

| Failure while “logging is enabled” | Detection evidence | Recovery action |
|----|----|----|
| Event selectors exclude relevant data or management events | Configuration diff, coverage canary and expected-event reconciliation | Restore reviewed selectors and backfill from another available source where possible |
| Organization trail scope or ownership changes | `UpdateTrail`, organization configuration, member-account coverage inventory | Restore delegated administration and organization scope |
| S3 or CloudWatch delivery fails | `get-trail-status` errors, object freshness and delivery latency | Repair destination policy, role, endpoint or key; confirm resumed delivery |
| KMS key policy, disablement or deletion blocks reads | KMS events, decrypt failures, archive read canary | Use protected key administration and tested recovery; do not assume retained bytes remain readable |
| SIEM connector unhealthy | Connector status, zero/low volume, source-to-table lag | Fail over or repair ingestion and reconcile gaps from archive |
| Parser/schema or timestamp drift | Null-rate, unknown-field, clock-skew and ingestion-time monitors | Version parser/query, quarantine malformed rows, reprocess where supported |
| Detection disabled or scheduler fails | Rule-state audit and expected canary alert | Restore signed/reviewed content and investigate the change |
| Alert routing or response automation deleted | Delivery acknowledgement, dead-letter queue, deployment drift | Restore from reviewed source and use manual incident path |

## Schema-reviewed Sentinel analytic

**Evidence label: illustrative KQL; columns schema-reviewed; no live execution.** Microsoft's current table reference exposes `UserAgent` directly. Do not attempt to derive it from `RequestParameters`.

```
AWSCloudTrail
| where EventSource =~ "cloudtrail.amazonaws.com"
| where EventName in~ (
    "StopLogging",
    "DeleteTrail",
    "UpdateTrail",
    "PutEventSelectors",
    "DeleteEventDataStore",
    "StopEventDataStoreIngestion"
)
| project
    TimeGenerated,
    AwsEventId,
    EventName,
    EventSource,
    UserIdentityArn,
    UserIdentityType,
    SessionIssuerUserName,
    SourceIpAddress,
    UserAgent,
    AWSRegion,
    RecipientAccountId,
    ErrorCode,
    ErrorMessage,
    RequestParameters
| order by TimeGenerated desc
```

The query finds attempts, including failed calls. Promotion to an alert rule needs a defined schedule and lookback, ingestion-delay allowance, deduplication key (for example `AwsEventId`), entity mapping, rule owner, severity logic, and tests using tenant-approved sample events. Verify field population in the connected workspace: schema existence does not guarantee every connector version populates every column for every event.

## Signal quality and expected false positives

High signal comes from context, not from suppressing all administrative behavior. Enrich with approved change windows, actor type, assumed-role issuer, source network, account purpose, trail ARN or event data store, change ticket, error result, and whether logging coverage actually decreased.

- **Expected legitimate cases:** approved trail maintenance, event-selector tuning, migration between destinations, controlled event-data-store retirement, and disaster-recovery exercises.
- **Suspicious cases:** unapproved changes, unfamiliar actor/session issuer, activity outside a window, public or novel source address, simultaneous KMS/S3 policy changes, or a change followed by delivery/ingestion loss.
- **Do not suppress blindly:** automation roles and AWS service principals can be compromised or misconfigured. Require the expected role, workflow, source, target, and change context.

## Safe automated response

One uncorroborated signal should not automatically delete keys, revoke broad sessions, or disable a shared administrator. Begin with evidence capture and notification. Escalate to containment only when confidence, asset criticality, and the action's blast radius satisfy a documented policy.

| Property | Required design |
|----|----|
| Idempotency | Stable incident/action key; repeated delivery produces the same bounded state |
| Allowlists and guardrails | Protected resources, principals, accounts, and operations that automation cannot alter |
| Protected identity | Dedicated role, exact actions/resources/conditions, no privilege-management wildcard |
| Evidence preservation | Record triggering event, enrichment, decision, API request/result and pre-change state |
| Canary and report-only rollout | Measure decisions and false positives before write authority is enabled |
| False-positive handling | Time-bounded suppression tied to exact change context and post-change review |
| Rollback | Known inverse operation, ownership, deadline and validation of restored access |
| Break glass | Separately protected human path that is logged and exercised |
| Maximum blast radius | One account/resource/session per execution or another explicit cap; concurrency bounded |

## Cases that should fail

**This is the test plan I'd run against a live Sentinel workspace — I haven't executed it for this write-up.**

| Test | Expected evidence |
|----|----|
| Approved `UpdateTrail` in a maintenance window | Alert enriched as expected change; no destructive response |
| Unauthorized `StopLogging` | One deduplicated alert with actor, account, region and direct `UserAgent` field |
| Failed `DeleteTrail` | Attempt retained with `ErrorCode`/`ErrorMessage`; severity reflects failure plus context |
| Selector removes a canary data event | Configuration alert and expected-event coverage monitor fire |
| Archive delivery blocked | Delivery-status and object-freshness alarms fire independently of the analytic |
| SIEM connector paused | Ingestion freshness alarm; archive remains available for reconciliation |
| Detection rule disabled | Rule-state or canary monitor alerts through an independent route |
| Duplicate event delivery | Idempotent incident and action; no repeated containment |
| Response target on protected allowlist | Write action denied and escalated to a human |
| Rollback invoked | Pre-state restored and independently verified |

## Operations, rollout and rollback

1. Inventory sources, selectors, destinations, keys, connectors, parsers, rules, routes, and response identities.
2. Add source-to-archive and source-to-SIEM freshness/volume canaries.
3. Run the analytic as a hunting query; compare to approved maintenance history.
4. Promote to alert-only with explicit ownership, deduplication and SLOs.
5. Canary automation in report-only mode, then grant the minimum write action to a small scope.
6. Exercise connector loss, KMS read failure, duplicate alerts, dead-letter handling, break glass and rollback.

Rollback detection content by version, not by disabling the entire detection category. If response automation behaves incorrectly, remove its write authority or disable the exact action while preserving alerting and evidence capture.

## What's still not solved

Gaps in what the cloud provider even logs, activity that was intentionally left unlogged, delayed delivery, a compromised admin who's supposed to be independent, encrypted archives you can no longer read, admin abuse that looks just like routine maintenance, schema changes, blind spots across regions or accounts, a SIEM that goes down, and containment actions that knock out something critical — all of that is still on the table. Detection shortens how long it takes to find out something happened; it's not a reason to skip preventive controls.

## References

- [Microsoft Azure Monitor `AWSCloudTrail` table schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/awscloudtrail)
- [Microsoft `AWSCloudTrail` sample queries](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/queries/awscloudtrail)
- [AWS CloudTrail operation and trail delivery](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/how-cloudtrail-works.html)
- [AWS CloudTrail organization-trail delivery troubleshooting](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-troubleshooting.html)
- [AWS CloudTrail data-event selectors](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html)
- [Amazon S3 Object Lock behavior and retention modes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
- [Amazon S3 Object Lock considerations, governance bypass and KMS limitation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-managing.html)
