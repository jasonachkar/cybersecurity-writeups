# 4. Detection Engineering & Threat Hunting

> The first three sections reduce *attack surface*. Detection engineering verifies they're holding and catches the residual risk. The discipline is: **get the right telemetry, shape it efficiently, write high-signal analytics as code, map them to adversary behavior, and validate they actually fire.** This section uses **Microsoft Sentinel + Azure Monitor** and **Kusto Query Language (KQL)**.

> ⚠️ **Tuning note:** the KQL below is written as **hunting starting points**. Table and column names vary by connector and by whether logs land in resource-specific tables (e.g., `StorageBlobLogs`) or `AzureDiagnostics`. Validate against *your* schema and baseline thresholds before promoting any query to an alerting rule.

**Contents**
- [4.1 Advanced telemetry orchestration](#41-advanced-telemetry-orchestration)
- [4.2 Practical KQL & analytics](#42-practical-kql--analytics)
- [4.3 Detection-as-code & operationalization](#43-detection-as-code--operationalization)
- [Best practices summary](#best-practices-summary)
- [Further reading](#further-reading)

---

## 4.1 Advanced telemetry orchestration

High-fidelity detection depends on **complete, normalized, cost-controlled** logging. Decide deliberately what to collect, where it lands, and how long it's retained.

### Core data sources (Azure)

| Source | Captures | Detects (examples) |
|--------|----------|--------------------|
| **Entra ID sign-in logs** (`SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AADServicePrincipalSignInLogs`) | Interactive/non-interactive/SP auth, device, location, risk | AiTM, impossible travel, SP abuse |
| **Entra ID audit logs** (`AuditLogs`) | Directory changes, **PIM**, consent grants, app role assignments | Consent phishing, PIM abuse, backdoor app credentials |
| **Azure Activity** (`AzureActivity`) | Control-plane (ARM) writes/deletes | Privilege escalation actions, resource tampering |
| **Key Vault logs** (`AzureDiagnostics` / `AZKVAuditLogs`) | Secret/key/cert operations | Mass secret retrieval, exfil precursor |
| **Storage logs** (`StorageBlobLogs`) | Blob data-plane reads/writes | Bulk download / exfiltration |
| **NSG flow logs / VNet flow logs** | Network 5-tuple + allow/deny | Lateral movement, C2 beaconing, exfil over 443 |
| **Defender XDR / Defender for Cloud alerts** | Endpoint, cloud posture, workload alerts | Correlate signals across layers |

### Enabling and **enforcing** diagnostic settings

Per-resource diagnostic settings route logs to a **Log Analytics workspace** (for analytics) and optionally to **Event Hubs** (streaming to third parties) and **Storage** (cheap long-term retention). At enterprise scale, configure them **manually nowhere** — enforce with **Azure Policy** `DeployIfNotExists` at the management-group level so every current and future resource is auto-onboarded:

```
Azure Policy initiative (assigned at MG root):
  - "Deploy diagnostic settings for <resourceType> to Log Analytics"   [DeployIfNotExists]
  - applies to Key Vault, Storage, NSGs, Activity Log, Entra diagnostic settings, ...
  - remediation task backfills existing resources
=> Result: telemetry coverage becomes a guaranteed property of the platform, not a checklist.
```

> **Coverage gaps are silent.** A resource with no diagnostic settings produces no logs and therefore no detections — an attacker's best friend. Policy-enforced onboarding closes this.

### Data Collection Rules (DCRs) — shape before you pay

Azure Monitor **DCRs** let you **filter, transform, and route** data at ingestion:

- **Drop noise** (verbose/health-probe events) to cut cost and speed queries.
- **Project only needed columns**; redact sensitive fields.
- **Route** high-value security data to an analytics tier and bulk/low-value data to a cheaper **Auxiliary/Basic logs** tier or archive.
- Map to **custom tables** (`*_CL`) for bespoke sources.

```kusto
// Example DCR ingestion-time transform (KQL): keep only failed/risky sign-ins in the hot tier
source
| where ResultType != 0 or RiskLevelDuringSignIn in ("high","medium")
| project TimeGenerated, UserPrincipalName, IPAddress, ResultType, RiskLevelDuringSignIn, AppDisplayName
```

### Third-party & multi-cloud ingestion

- **Event Hub** as a universal ingestion point for sources that can't write to LA directly (AWS CloudTrail, Okta, Zscaler, firewalls).
- **Sentinel content hub** solutions/data connectors for common SaaS and clouds (AWS, GCP).
- **ASIM (Advanced Security Information Model):** normalize heterogeneous logs into common schemas (e.g., `imAuthentication`, `imNetworkSession`) so a *single* detection works across sources. Write detections against ASIM parsers, not raw vendor tables, to avoid one rule per product.

---

## 4.2 Practical KQL & analytics

### Detecting PIM activation immediately followed by resource changes

Pattern: a user activates a privileged role via PIM, then makes control-plane changes within the hour — normal for legit ops, but the *timing + nature* of changes can flag abuse (e.g., activation → role assignment → data export).

```kusto
let lookback = 14d;
let correlationWindow = 1h;
// PIM activations from Entra audit logs
let activations =
    AuditLogs
    | where TimeGenerated > ago(lookback)
    | where LoggedByService == "PIM"
    | where OperationName has "activation"        // "Add member to role completed (PIM activation)"
    | extend Actor = tostring(InitiatedBy.user.userPrincipalName)
    | extend RoleName = tostring(TargetResources[0].displayName)
    | project ActivationTime = TimeGenerated, Actor, RoleName;
// Successful control-plane writes
let deployments =
    AzureActivity
    | where TimeGenerated > ago(lookback)
    | where ActivityStatusValue == "Success"
    | where OperationNameValue has_any ("write", "action", "delete")
    | project DeploymentTime = TimeGenerated, Caller, Operation = OperationNameValue, ResourceId = _ResourceId;
activations
| join kind=inner deployments on $left.Actor == $right.Caller
| where DeploymentTime between (ActivationTime .. ActivationTime + correlationWindow)
| project ActivationTime, DeploymentTime, Actor, RoleName, Operation, ResourceId
| order by ActivationTime desc
```

**Off-hours activations** (high-signal, low-noise variant):

```kusto
let businessStart = 7;   // local business hours
let businessEnd   = 19;
AuditLogs
| where TimeGenerated > ago(30d)
| where LoggedByService == "PIM" and OperationName has "activation"
| extend hour = datetime_part("Hour", TimeGenerated), dow = dayofweek(TimeGenerated)
| where hour < businessStart or hour >= businessEnd or dow == 0d or dow == 6d   // nights/weekends
| extend Actor = tostring(InitiatedBy.user.userPrincipalName),
         RoleName = tostring(TargetResources[0].displayName),
         Result = tostring(ResultReason)
| project TimeGenerated, Actor, RoleName, Result
| order by TimeGenerated desc
```

### Detecting anomalous / unusual API & sign-in volume

Use time-series anomaly detection to flag users whose successful sign-in volume departs from their own baseline:

```kusto
let lookback = 21d;
let step = 1h;
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == 0                                  // successful
| make-series Count = count() default = 0
    on TimeGenerated from ago(lookback) to now() step step
    by UserPrincipalName
| extend (anomalies, score, baseline) =
    series_decompose_anomalies(Count, 2.5, -1, 'linefit')   // 2.5 = sensitivity
| mv-expand TimeGenerated to typeof(datetime),
            Count to typeof(long),
            anomalies to typeof(long),
            score to typeof(double),
            baseline to typeof(double)
| where anomalies > 0 and Count > baseline                 // spikes only
| project TimeGenerated, UserPrincipalName, Count, baseline = round(baseline, 1), score
| order by score desc
```

**Rare app / resource access** (first-seen / low-frequency hunting):

```kusto
SigninLogs
| where TimeGenerated > ago(30d) and ResultType == 0
| summarize Hits = count(), Users = dcount(UserPrincipalName),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by AppDisplayName, ResourceDisplayName, ClientAppUsed
| where Hits <= 5 or Users == 1                            // rarely used = worth a look
| order by Hits asc
```

### Correlating Key Vault with data access (cross-resource exfiltration)

A classic exfil chain: an identity pulls secrets from Key Vault, then uses them to read large volumes of data. Joining the two telemetry streams on the **actor** within a time window surfaces it:

```kusto
let window = 1h;
let sizeThreshold = 100 * 1024 * 1024;   // 100 MB
// Secret/key retrievals from Key Vault
let kvAccess =
    AzureDiagnostics
    | where ResourceType == "VAULTS"
    | where OperationName in ("SecretGet", "KeyGet", "CertificateGet")
    | extend Actor = coalesce(column_ifexists("identity_claim_upn_s", ""),
                              column_ifexists("identity_claim_appid_g", ""),
                              CallerIPAddress)
    | project KvTime = TimeGenerated, Actor, CallerIPAddress, Vault = Resource, OperationName;
// Bulk blob reads
let storageReads =
    StorageBlobLogs
    | where OperationName == "GetBlob"
    | extend Actor = coalesce(column_ifexists("RequesterUpn", ""),
                              column_ifexists("RequesterAppId", ""),
                              CallerIpAddress)
    | project StTime = TimeGenerated, Actor, AccountName, Uri, Bytes = ResponseBodySize;
kvAccess
| join kind=inner storageReads on Actor
| where StTime between (KvTime .. KvTime + window)
| summarize SecretOps = dcount(Vault), BytesRead = sum(Bytes), Blobs = count(),
            FirstSecret = min(KvTime), LastRead = max(StTime)
    by Actor
| where BytesRead > sizeThreshold
| order by BytesRead desc
```

### Reusable functions

Save common logic as a **Sentinel saved function** so detections stay DRY and consistent:

```kusto
// Save as function: PrivilegedActors()
AuditLogs
| where LoggedByService == "PIM" and OperationName has "activation"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| distinct Actor
// ...then in any detection:  | where Caller in (PrivilegedActors())
```

---

## 4.3 Detection-as-code & operationalization

### Treat detections like software

- **Version control** analytics rules (Sentinel supports repository connections to GitHub/Azure DevOps). Rules ship via PRs with review — the same discipline as [Section 2](./devsecops-pipeline-hardening.md).
- **CI for detections:** lint/validate KQL syntax, run unit tests against sample data, and deploy via pipeline (ARM/Bicep templates of `Microsoft.SecurityInsights/alertRules`).
- **Parameterize thresholds** so they're tunable without rewriting logic.

### From hunting query to analytics rule

| Aspect | Guidance |
|--------|----------|
| **Schedule** | Run frequency ≈ the detection's needed timeliness; align lookback to frequency + grace. |
| **Threshold & grouping** | Group results into incidents by entity (account/host/IP) to avoid one-alert-per-row. |
| **Suppression** | Add suppression/throttling so a noisy condition doesn't reopen incidents every run. |
| **Entity mapping** | Map account, IP, host, resource entities so incidents are investigable and correlatable. |
| **Enrichment** | Join watchlists (VIP users, crown-jewel resources, known-good service IPs) to raise/lower priority. |

### Map every detection to MITRE ATT&CK

Tag each rule with ATT&CK tactics/techniques to measure **coverage** and find blind spots:

| Detection (above) | ATT&CK technique |
|-------------------|------------------|
| PIM activation → resource change | T1078.004 *Valid Accounts: Cloud Accounts*; T1098 *Account Manipulation* |
| Anomalous sign-in volume | T1078 *Valid Accounts*; T1110 *Brute Force* (paired) |
| Consent grant to high-priv app | T1528 *Steal Application Access Token*; T1550 *Use Alternate Auth Material* |
| Key Vault → bulk Storage read | T1530 *Data from Cloud Storage*; T1567 *Exfiltration Over Web Service* |
| In-place change to immutable host | T1505/T1543 *Persistence* |

Build a coverage matrix; prioritize new detections against **uncovered, high-likelihood** techniques for your environment.

### Validate — don't assume it fires

- **Atomic Red Team / Stratus Red Team** (cloud-native) to safely simulate techniques (e.g., create a consent grant, mass-read a bucket) and confirm the detection triggers.
- **Purple-team exercises:** run the attack, measure **detection latency** and whether the incident was investigable end-to-end.
- **Track detection health:** alert on rules that stop producing results (a sign of a broken connector or schema change) — a "detector for your detectors."

---

## Best practices summary

- **Guarantee coverage:** enforce diagnostic settings via Azure Policy `DeployIfNotExists`; no resource ships without telemetry.
- **Shape at ingestion:** DCRs to drop noise, project columns, and tier data for cost and performance.
- **Normalize with ASIM** so one detection spans many sources/clouds.
- **Write high-signal KQL:** baseline per-entity (anomaly detection), correlate across resources (Key Vault ↔ Storage), prefer rare/first-seen and off-hours pivots.
- **Detection-as-code:** version control, CI validation, parameterized thresholds, suppression, entity mapping.
- **Map to MITRE ATT&CK** and **validate with simulations**; monitor detector health.

---

## Further reading

- MITRE ATT&CK (Enterprise & Cloud) — <https://attack.mitre.org/matrices/enterprise/cloud/>
- Microsoft Sentinel documentation — <https://learn.microsoft.com/azure/sentinel/>
- Microsoft — *Advanced SIEM Information Model (ASIM)* — <https://learn.microsoft.com/azure/sentinel/normalization>
- Microsoft — *Data Collection Rules in Azure Monitor* — <https://learn.microsoft.com/azure/azure-monitor/essentials/data-collection-rule-overview>
- KQL reference (`make-series`, `series_decompose_anomalies`) — <https://learn.microsoft.com/azure/data-explorer/kusto/query/>
- Microsoft — *Manage Sentinel content as code (repositories)* — <https://learn.microsoft.com/azure/sentinel/ci-cd>
- NIST SP 800-92, *Guide to Computer Security Log Management* — <https://csrc.nist.gov/pubs/sp/800/92/final>
- Stratus Red Team (cloud attack simulation) — <https://stratus-red-team.cloud/> · Atomic Red Team — <https://github.com/redcanaryco/atomic-red-team>

---

[← Previous: Cloud Security Architecture](./cloud-security-architecture.md) · [Back to overview](./README.md)
