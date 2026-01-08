# Monitoring and Alerting Guide

This document provides detailed guidance for monitoring Microsoft Entra ID security events and configuring alerts for identity-related threats.

## Overview

Effective identity security requires comprehensive monitoring and alerting. Without visibility into authentication events, configuration changes, and risk detections, security incidents go undetected and unaddressed.

---

## Log Types and Sources

### Core Entra ID Logs

| Log Type | Content | Retention (Entra ID) |
|----------|---------|----------------------|
| Sign-in logs | All authentication events | 30 days |
| Audit logs | Configuration and administrative changes | 30 days |
| Provisioning logs | User/group sync events | 30 days |
| Risk detections | Identity Protection events | 90 days |

### Extended Retention

For compliance and investigation purposes, export logs to:
- **Azure Log Analytics**: Query and analyze with KQL
- **Azure Storage**: Long-term archival
- **Event Hub**: Real-time streaming to SIEM

---

## Diagnostic Settings Configuration

### Step 1: Create Log Analytics Workspace

1. Navigate to **Azure Portal** > **Log Analytics workspaces**
2. Click **+ Create**
3. Configure:
   - Subscription: Your subscription
   - Resource group: Security or Monitoring resource group
   - Name: `law-security-prod`
   - Region: Your primary region
4. Click **Review + Create**

### Step 2: Configure Diagnostic Settings

1. Navigate to **Entra ID** > **Diagnostic settings**
2. Click **+ Add diagnostic setting**
3. Configure:
   - Diagnostic setting name: `EntraID-AllLogs-LAW`
   - **Logs to export:**
     - AuditLogs
     - SignInLogs
     - NonInteractiveUserSignInLogs
     - ServicePrincipalSignInLogs
     - ManagedIdentitySignInLogs
     - ProvisioningLogs
     - ADFSSignInLogs (if applicable)
     - RiskyUsers
     - UserRiskEvents
     - NetworkAccessTrafficLogs
     - RiskyServicePrincipals
     - ServicePrincipalRiskEvents
   - **Destination:**
     - Send to Log Analytics workspace: Selected
     - Workspace: `law-security-prod`
4. Click **Save**

---

## Key Monitoring Scenarios

### Scenario 1: Failed Sign-In Monitoring

**Purpose:** Detect brute force and password spray attacks

**KQL Query:**
```kql
SigninLogs
| where ResultType != 0  // Failed sign-ins
| where TimeGenerated > ago(24h)
| summarize 
    FailureCount = count(),
    DistinctUsers = dcount(UserPrincipalName),
    Users = make_set(UserPrincipalName, 10)
  by IPAddress, ResultType, ResultDescription
| where FailureCount > 10
| sort by FailureCount desc
```

**Alert Threshold:** More than 50 failed sign-ins from single IP in 1 hour

### Scenario 2: Successful Sign-In After Multiple Failures

**Purpose:** Detect successful brute force attacks

**KQL Query:**
```kql
let FailedSignIns = SigninLogs
| where ResultType != 0
| where TimeGenerated > ago(1h)
| summarize FailCount = count() by UserPrincipalName, IPAddress
| where FailCount > 5;

SigninLogs
| where ResultType == 0  // Successful
| where TimeGenerated > ago(1h)
| join kind=inner FailedSignIns on UserPrincipalName, IPAddress
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, FailCount
```

**Alert Threshold:** Any match

### Scenario 3: Sign-In from New Country

**Purpose:** Detect compromised credentials used from unexpected locations

**KQL Query:**
```kql
let KnownCountries = SigninLogs
| where TimeGenerated between (ago(30d) .. ago(1d))
| where ResultType == 0
| summarize Countries = make_set(Location) by UserPrincipalName;

SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == 0
| join kind=leftanti KnownCountries on UserPrincipalName
| project TimeGenerated, UserPrincipalName, Location, IPAddress, AppDisplayName
```

### Scenario 4: Impossible Travel Detection

**Purpose:** Detect sign-ins from geographically impossible locations

**KQL Query:**
```kql
SigninLogs
| where ResultType == 0
| where TimeGenerated > ago(24h)
| project TimeGenerated, UserPrincipalName, Location, IPAddress
| sort by UserPrincipalName, TimeGenerated asc
| serialize
| extend PrevTime = prev(TimeGenerated, 1), PrevLocation = prev(Location, 1), PrevUser = prev(UserPrincipalName, 1)
| where UserPrincipalName == PrevUser
| where Location != PrevLocation
| extend TimeDiffMinutes = datetime_diff('minute', TimeGenerated, PrevTime)
| where TimeDiffMinutes < 60  // Less than 1 hour between different locations
| project TimeGenerated, UserPrincipalName, Location, PrevLocation, TimeDiffMinutes
```

### Scenario 5: Privileged Role Assignment Changes

**Purpose:** Detect unauthorized privilege escalation

**KQL Query:**
```kql
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName has_any ("Add member to role", "Add eligible member to role", "Remove member from role")
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| extend RoleName = tostring(TargetResources[0].displayName)
| extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, OperationName, RoleName, TargetUser, InitiatedBy
```

**Alert Threshold:** Any change to Global Administrator, Privileged Role Administrator, or Security Administrator

### Scenario 6: Conditional Access Policy Changes

**Purpose:** Detect security policy modifications

**KQL Query:**
```kql
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName has_any ("Add conditional access policy", "Update conditional access policy", "Delete conditional access policy")
| extend PolicyName = tostring(TargetResources[0].displayName)
| extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, OperationName, PolicyName, InitiatedBy, Result
```

**Alert Threshold:** Any change

### Scenario 7: Legacy Authentication Attempts

**Purpose:** Monitor for legacy authentication even when blocked

**KQL Query:**
```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ClientAppUsed in ("Exchange ActiveSync", "IMAP4", "POP3", "Authenticated SMTP", "Other clients")
| summarize AttemptCount = count() by UserPrincipalName, ClientAppUsed, ResultType
| sort by AttemptCount desc
```

### Scenario 8: MFA Method Changes

**Purpose:** Detect potential MFA bypass attempts

**KQL Query:**
```kql
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName has_any ("User registered security info", "User deleted security info", "User changed default security info")
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| extend Method = tostring(TargetResources[0].displayName)
| project TimeGenerated, OperationName, TargetUser, Method, Result
```

**Alert Threshold:** Any change for privileged users; review patterns for regular users

### Scenario 9: Break-Glass Account Usage

**Purpose:** Alert on any use of emergency access accounts

**KQL Query:**
```kql
let BreakGlassAccounts = dynamic(["EmergencyAccess1@contoso.com", "EmergencyAccess2@contoso.com"]);
SigninLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName in (BreakGlassAccounts)
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, ResultType
```

**Alert Threshold:** Any sign-in attempt (successful or failed)

### Scenario 10: Application Consent Grants

**Purpose:** Detect consent phishing attacks

**KQL Query:**
```kql
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName has_any ("Consent to application", "Add delegated permission grant", "Add app role assignment to service principal")
| extend AppName = tostring(TargetResources[0].displayName)
| extend ConsentedBy = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, OperationName, AppName, ConsentedBy, Result
```

**Alert Threshold:** Review all admin consents; alert on high-privilege consents

---

## Alert Configuration

### Creating Alert Rules in Log Analytics

1. Navigate to **Log Analytics workspace** > **Alerts**
2. Click **+ New alert rule**
3. Configure:
   - Scope: Your workspace
   - Condition: Custom log search
   - Alert logic: Based on your query results
   - Actions: Action group (email, SIEM, webhook)
   - Details: Name, severity, frequency

### Recommended Alert Severities

| Alert Type | Severity | Frequency |
|------------|----------|-----------|
| Break-glass account usage | Critical (Sev 0) | Every 5 minutes |
| Global Admin role change | High (Sev 1) | Every 5 minutes |
| Conditional Access change | High (Sev 1) | Every 15 minutes |
| Impossible travel | Medium (Sev 2) | Every 15 minutes |
| Multiple failed sign-ins | Medium (Sev 2) | Every 15 minutes |
| Legacy auth attempts | Low (Sev 3) | Every hour |

### Action Groups Configuration

Create action groups for different response requirements:

**Critical-Response:**
- Email: SOC team distribution list
- SMS: On-call security analyst
- Webhook: Incident management system
- Logic App: Automated containment

**High-Priority:**
- Email: Security team distribution list
- Webhook: Ticketing system

**Standard:**
- Email: Security mailbox

---

## Dashboard Creation

### Creating Security Dashboard

1. Navigate to **Log Analytics workspace** > **Workbooks**
2. Click **+ New**
3. Add visualizations:

**Sign-In Summary:**
```kql
SigninLogs
| where TimeGenerated > ago(7d)
| summarize 
    TotalSignIns = count(),
    SuccessfulSignIns = countif(ResultType == 0),
    FailedSignIns = countif(ResultType != 0)
  by bin(TimeGenerated, 1d)
| render timechart
```

**Risk Detection Trend:**
```kql
AADUserRiskEvents
| where TimeGenerated > ago(30d)
| summarize Count = count() by bin(TimeGenerated, 1d), RiskLevel
| render timechart
```

**Top Failed Sign-In Locations:**
```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != 0
| summarize Count = count() by Location
| top 10 by Count
| render piechart
```

**Application Sign-In Distribution:**
```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| summarize Count = count() by AppDisplayName
| top 10 by Count
| render barchart
```

---

## SIEM Integration

### Microsoft Sentinel

For organizations using Microsoft Sentinel:

1. Add **Microsoft Entra ID** data connector
2. Enable all log types
3. Deploy built-in analytics rules:
   - Anomalous sign-in location
   - Brute force attack
   - Credential access after breach
   - Excessive password reset
   - New country sign-in

### Third-Party SIEM

For Splunk, QRadar, or other SIEM:

1. Configure Event Hub export in Diagnostic Settings
2. Deploy appropriate connector/forwarder
3. Create parsing rules for Entra ID log format
4. Import or create correlation rules

---

## Incident Response Integration

### Automated Response with Logic Apps

**Example: Disable User on High Risk**

```json
{
  "trigger": "When a risky user is detected",
  "actions": [
    {
      "condition": "Risk level equals High",
      "action": "Block user sign-in",
      "then": "Notify security team",
      "finally": "Create incident ticket"
    }
  ]
}
```

### Incident Response Playbook

**High-Risk User Detected:**

1. **Triage (5 minutes)**
   - Review risk detections
   - Check user's recent sign-in activity
   - Determine if legitimate user or attacker

2. **Containment (15 minutes)**
   - Revoke all sessions
   - Reset password (if compromised)
   - Block sign-in (if needed)

3. **Investigation (1 hour)**
   - Review all recent activity
   - Check for data access
   - Identify persistence mechanisms

4. **Recovery (Variable)**
   - Restore user access (if false positive)
   - Implement additional controls
   - Document lessons learned

---

## Compliance Reporting

### Regular Reports

**Weekly:**
- Failed sign-in summary
- Risk detection summary
- Privileged access changes

**Monthly:**
- Sign-in trends
- MFA adoption metrics
- Policy effectiveness

**Quarterly:**
- Access review completion
- Security posture improvements
- Compliance status

### Report Query: Monthly Executive Summary

```kql
let StartDate = startofmonth(ago(31d));
let EndDate = startofmonth(now());

union
(
  SigninLogs
  | where TimeGenerated between (StartDate .. EndDate)
  | summarize 
      TotalSignIns = count(),
      UniqueUsers = dcount(UserPrincipalName),
      FailedSignIns = countif(ResultType != 0),
      MFARequired = countif(AuthenticationRequirement == "multiFactorAuthentication")
  | extend ReportType = "SignInSummary"
),
(
  AADUserRiskEvents
  | where TimeGenerated between (StartDate .. EndDate)
  | summarize 
      HighRiskEvents = countif(RiskLevel == "high"),
      MediumRiskEvents = countif(RiskLevel == "medium"),
      TotalRiskEvents = count()
  | extend ReportType = "RiskSummary"
)
```

---

## Related Documentation

- [README.md](README.md) - Main tutorial
- [conditional-access-policies.md](conditional-access-policies.md) - CA policy reference
- [pim-configuration.md](pim-configuration.md) - PIM setup guide
- [identity-protection.md](identity-protection.md) - Identity Protection configuration
