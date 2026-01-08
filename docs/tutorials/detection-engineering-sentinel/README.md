# Detection Engineering with Microsoft Sentinel

A comprehensive guide to building, deploying, and managing detection rules in Microsoft Sentinel using KQL (Kusto Query Language).

## Table of Contents

1. [Introduction to Detection Engineering](#introduction-to-detection-engineering)
2. [Microsoft Sentinel Architecture](#microsoft-sentinel-architecture)
3. [KQL Fundamentals for Detection](#kql-fundamentals-for-detection)
4. [Analytics Rules](#analytics-rules)
5. [Entity Mapping](#entity-mapping)
6. [MITRE ATT&CK Integration](#mitre-attck-integration)
7. [Threat Hunting](#threat-hunting)
8. [Automation with Playbooks](#automation-with-playbooks)
9. [Detection Examples](#detection-examples)
10. [Best Practices](#best-practices)

---

## Introduction to Detection Engineering

Detection engineering is the systematic approach to identifying malicious activity in your environment through the creation, tuning, and maintenance of detection rules. In Microsoft Sentinel, this involves:

- **Analytics Rules**: Automated detection queries that run on a schedule
- **Hunting Queries**: Ad-hoc queries for proactive threat hunting
- **Workbooks**: Visualizations for monitoring and investigation
- **Playbooks**: Automated response actions via Logic Apps

### The Detection Lifecycle

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  Research   │───▶│   Develop   │───▶│   Deploy    │───▶│    Tune     │
│  & Design   │    │   & Test    │    │  & Monitor  │    │  & Improve  │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
       ▲                                                        │
       └────────────────────────────────────────────────────────┘
```

### Key Data Sources

| Data Source | Table Name | Use Cases |
|-------------|------------|-----------|
| Azure AD Sign-ins | SigninLogs | Authentication attacks, impossible travel |
| Azure AD Audit | AuditLogs | Permission changes, app registrations |
| Microsoft 365 | OfficeActivity | Email threats, SharePoint access |
| Defender for Endpoint | DeviceEvents, DeviceProcessEvents | Endpoint threats |
| Windows Security | SecurityEvent | Local authentication, process execution |
| Azure Activity | AzureActivity | Cloud resource changes |
| Syslog | Syslog | Linux/network device logs |
| Common Security Log | CommonSecurityLog | Firewall, proxy logs (CEF format) |

---

## Microsoft Sentinel Architecture

### Core Components

```
┌─────────────────────────────────────────────────────────────────┐
│                     Microsoft Sentinel                          │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │    Data      │  │  Analytics   │  │   Threat     │          │
│  │  Connectors  │  │    Rules     │  │ Intelligence │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│         │                 │                  │                  │
│         ▼                 ▼                  ▼                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Log Analytics Workspace                     │   │
│  │                    (KQL Queries)                         │   │
│  └─────────────────────────────────────────────────────────┘   │
│         │                 │                  │                  │
│         ▼                 ▼                  ▼                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   Incidents  │  │   Hunting    │  │  Workbooks   │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│         │                                                       │
│         ▼                                                       │
│  ┌──────────────┐  ┌──────────────┐                            │
│  │  Automation  │  │  Playbooks   │                            │
│  │    Rules     │  │ (Logic Apps) │                            │
│  └──────────────┘  └──────────────┘                            │
└─────────────────────────────────────────────────────────────────┘
```

### Rule Types

| Rule Type | Description | Use Case |
|-----------|-------------|----------|
| Scheduled | Runs KQL query on schedule | Custom detections |
| NRT (Near Real-Time) | Runs every minute | Time-critical alerts |
| Fusion | ML-based correlation | Advanced multi-stage attacks |
| Microsoft Security | Imports alerts from MS products | Defender, MCAS alerts |
| Anomaly | ML-based anomaly detection | Behavioral analysis |

---

## KQL Fundamentals for Detection

### Essential Operators

```kql
// Basic filtering
TableName
| where TimeGenerated > ago(1d)
| where Column == "value"

// Projection (select columns)
| project TimeGenerated, UserPrincipalName, IPAddress

// Aggregation
| summarize Count = count() by UserPrincipalName

// Sorting
| order by Count desc

// Limiting results
| take 100
| top 10 by Count
```

### Time Functions

```kql
// Relative time
| where TimeGenerated > ago(1h)     // Last hour
| where TimeGenerated > ago(1d)     // Last day
| where TimeGenerated > ago(7d)     // Last 7 days

// Time binning
| summarize Count = count() by bin(TimeGenerated, 1h)

// Time of day
| extend HourOfDay = hourofday(TimeGenerated)
| extend DayOfWeek = dayofweek(TimeGenerated)

// Start/end of periods
| where TimeGenerated >= startofday(ago(7d))
| where TimeGenerated < startofday(now())
```

### String Operations

```kql
// Contains (case-insensitive)
| where CommandLine contains "mimikatz"

// Contains (case-sensitive)
| where CommandLine contains_cs "Mimikatz"

// Starts/ends with
| where FileName startswith "cmd"
| where FilePath endswith ".exe"

// Regular expressions
| where CommandLine matches regex @"(?i)invoke-.*expression"

// String extraction
| extend Domain = extract(@"@(.+)$", 1, UserPrincipalName)
```

### Join Operations

```kql
// Inner join - only matching records
TableA
| join kind=inner TableB on CommonColumn

// Left outer join - all from left, matching from right
TableA
| join kind=leftouter TableB on CommonColumn

// Anti join - records in A not in B
TableA
| join kind=leftanti TableB on CommonColumn

// Multiple conditions
TableA
| join kind=inner TableB on $left.Col1 == $right.Col2
```

### Let Statements and Variables

```kql
// Define variables
let timeRange = 1d;
let threshold = 10;
let suspiciousIPs = dynamic(["1.2.3.4", "5.6.7.8"]);

// Define subqueries
let failedLogins = SigninLogs
    | where ResultType != "0"
    | summarize FailCount = count() by UserPrincipalName;

// Use in main query
SigninLogs
| where TimeGenerated > ago(timeRange)
| where IPAddress in (suspiciousIPs)
| join kind=inner failedLogins on UserPrincipalName
| where FailCount > threshold
```

### Useful Functions

```kql
// Conditional logic
| extend Risk = iff(FailedAttempts > 10, "High", "Low")
| extend Risk = case(
    FailedAttempts > 20, "Critical",
    FailedAttempts > 10, "High",
    FailedAttempts > 5, "Medium",
    "Low"
)

// Null handling
| extend Value = coalesce(Column1, Column2, "Default")

// JSON parsing
| extend ParsedData = parse_json(AdditionalData)
| extend TargetUser = tostring(ParsedData.TargetUserName)

// Array operations
| mv-expand IPAddresses
| summarize IPs = make_set(IPAddress) by UserPrincipalName

// Row number and ranking
| serialize | extend RowNum = row_number()
```

---

## Analytics Rules

### Rule Configuration

**Query Settings:**

| Setting | Description | Recommendation |
|---------|-------------|----------------|
| Query Period | How far back to look | Match your detection window |
| Query Frequency | How often to run | Balance detection speed vs cost |
| Trigger Threshold | Minimum results to alert | Start at 0, tune as needed |
| Event Grouping | How to group alerts | Group by entity for deduplication |

**Common Patterns:**

```kql
// Query Period: 1 day, Frequency: 1 hour
// Looks back 24h every hour for overlap

// Query Period: 5 minutes, Frequency: 5 minutes  
// Near real-time detection (use NRT rules instead)

// Query Period: 14 days, Frequency: 1 day
// Good for statistical baseline detection
```

### Rule Template Structure

```kql
// Detection: [Name of Detection]
// MITRE ATT&CK: [Tactic] - [Technique ID]
// Data Source: [Required tables]
// Description: [What this detects]

let lookback = 1d;
let threshold = 5;

TableName
| where TimeGenerated > ago(lookback)
// Main detection logic
| where [conditions]
// Aggregation if needed
| summarize 
    Count = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by EntityColumn
// Apply threshold
| where Count > threshold
// Project for entity mapping
| project 
    TimeGenerated = LastSeen,
    Account = EntityColumn,
    Count,
    FirstSeen
```

### Creating a Scheduled Rule (Azure Portal)

1. Navigate to **Microsoft Sentinel** → **Analytics**
2. Click **Create** → **Scheduled query rule**
3. Configure:
   - **General**: Name, Description, Severity, MITRE tactics
   - **Set rule logic**: KQL query, entity mapping, scheduling
   - **Incident settings**: Grouping, alert limits
   - **Automated response**: Playbooks, automation rules

---

## Entity Mapping

Entity mapping links detected events to specific entities (users, hosts, IPs) for investigation and correlation.

### Supported Entity Types

| Entity Type | Key Identifiers | Example Fields |
|-------------|-----------------|----------------|
| Account | Name, UPNSuffix, AadUserId | UserPrincipalName, AccountName |
| Host | HostName, FQDN, AzureID | Computer, DeviceName |
| IP | Address | IPAddress, SourceIP |
| URL | Url | RequestUrl |
| File | Name, Directory, Hash | FileName, FilePath, SHA256 |
| Process | CommandLine, ProcessId | ProcessCommandLine |
| Mailbox | MailboxPrimaryAddress | RecipientEmailAddress |
| CloudApplication | AppId, Name | AppDisplayName |

### Entity Mapping Example

```kql
SigninLogs
| where ResultType == "50053"  // Account locked
| project 
    TimeGenerated,
    // Account entity
    UserPrincipalName,
    UserDisplayName,
    UserId,
    // IP entity  
    IPAddress,
    // Host entity (if available)
    DeviceDetail_displayName = tostring(DeviceDetail.displayName),
    // Additional context
    Location,
    AppDisplayName,
    ResultDescription
```

**In the rule configuration, map:**
- Account → UserPrincipalName (Name + UPNSuffix)
- IP → IPAddress (Address)
- Host → DeviceDetail_displayName (HostName)

---

## MITRE ATT&CK Integration

### Viewing Coverage

Microsoft Sentinel provides a MITRE ATT&CK matrix view showing:
- **Active coverage**: Currently enabled detection rules
- **Simulated coverage**: Available but not enabled rules
- **Gaps**: Techniques without detection rules

### Mapping Detections to MITRE

When creating rules, assign appropriate tactics and techniques:

| Tactic | Description | Example Techniques |
|--------|-------------|-------------------|
| Reconnaissance | Gathering information | T1595 Active Scanning |
| Initial Access | Getting in | T1566 Phishing, T1078 Valid Accounts |
| Execution | Running code | T1059 Command Scripting |
| Persistence | Maintaining access | T1098 Account Manipulation |
| Privilege Escalation | Getting higher access | T1078 Valid Accounts |
| Defense Evasion | Avoiding detection | T1070 Indicator Removal |
| Credential Access | Stealing credentials | T1110 Brute Force |
| Discovery | Learning the environment | T1087 Account Discovery |
| Lateral Movement | Moving around | T1021 Remote Services |
| Collection | Gathering target data | T1114 Email Collection |
| Exfiltration | Stealing data | T1048 Exfiltration Over Alternative Protocol |
| Impact | Damage/disruption | T1486 Data Encrypted for Impact |

### Coverage Analysis Query

```kql
// View analytics rules and their MITRE mapping
SentinelHealth
| where SentinelResourceType == "Analytics Rule"
| where TimeGenerated > ago(7d)
| summarize 
    LastRun = max(TimeGenerated),
    SuccessCount = countif(Status == "Success"),
    FailCount = countif(Status != "Success")
    by SentinelResourceName
| order by FailCount desc
```

---

## Threat Hunting

### Hunting Query Structure

```kql
// Hunting Query: [Name]
// Hypothesis: [What you're looking for]
// MITRE: [Tactic/Technique]

let timeRange = 14d;

// Main hunting logic
TableName
| where TimeGenerated > ago(timeRange)
| where [suspicious conditions]
// Enrich with context
| extend [additional fields]
// Summarize findings
| summarize 
    Occurrences = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by [grouping fields]
// Surface anomalies
| where Occurrences > [threshold] or [other conditions]
| order by Occurrences desc
```

### Hunting Workflow

1. **Form Hypothesis**: Based on threat intelligence, incidents, or MITRE gaps
2. **Write Query**: Create KQL to test hypothesis
3. **Execute & Analyze**: Run query, review results
4. **Bookmark Findings**: Save interesting results for investigation
5. **Create Detection**: Convert successful hunts to analytics rules

### Livestream Hunting

Real-time monitoring during active incidents:

```kql
// Run as livestream to monitor in real-time
SecurityEvent
| where TimeGenerated > ago(5m)
| where EventID in (4624, 4625)
| project TimeGenerated, Computer, Account, LogonType, IpAddress
```

---

## Automation with Playbooks

### Playbook Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Incident/     │────▶│   Automation     │────▶│    Playbook     │
│   Alert Created │     │   Rule           │     │  (Logic App)    │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                                          │
                        ┌─────────────────────────────────┼─────────────────────────────────┐
                        ▼                                 ▼                                 ▼
              ┌─────────────────┐               ┌─────────────────┐               ┌─────────────────┐
              │  Enrich Data    │               │  Notify Team    │               │  Take Action    │
              │  (IP lookup,    │               │  (Teams, Email, │               │  (Block IP,     │
              │   User info)    │               │   ServiceNow)   │               │   Disable user) │
              └─────────────────┘               └─────────────────┘               └─────────────────┘
```

### Common Playbook Actions

| Category | Actions |
|----------|---------|
| Enrichment | IP geolocation, Threat intelligence lookup, User details |
| Notification | Teams message, Email, ServiceNow ticket, PagerDuty |
| Containment | Disable user account, Block IP in firewall, Isolate device |
| Documentation | Add comment to incident, Update tags, Change severity |

### Playbook Triggers

| Trigger | Use Case |
|---------|----------|
| Incident trigger | Respond to incidents (recommended) |
| Alert trigger | Respond to individual alerts |
| Entity trigger | Run on specific entity (from investigation) |

### Required Permissions

- **Microsoft Sentinel Automation Contributor**: For Sentinel to run playbooks
- **Logic App Contributor**: To create and manage playbooks
- Specific API permissions for actions (e.g., User.ReadWrite.All for disabling users)

---

## Detection Examples

### 1. Brute Force Attack Detection

```kql
// Detection: Brute Force Attack Against Azure AD
// MITRE: Credential Access - T1110 Brute Force
// Data Source: SigninLogs

let threshold = 10;
let timeWindow = 10m;

SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType != "0"  // Failed sign-ins
| where ResultType !in ("50125", "50140")  // Exclude MFA prompts
| summarize 
    FailedAttempts = count(),
    DistinctUsers = dcount(UserPrincipalName),
    UserList = make_set(UserPrincipalName, 10),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by IPAddress, bin(TimeGenerated, timeWindow)
| where FailedAttempts > threshold
| extend 
    AttackType = iff(DistinctUsers == 1, "Brute Force", "Password Spray")
| project 
    TimeGenerated = LastAttempt,
    IPAddress,
    AttackType,
    FailedAttempts,
    DistinctUsers,
    UserList,
    Duration = LastAttempt - FirstAttempt
```

### 2. Password Spray Detection

```kql
// Detection: Password Spray Attack
// MITRE: Credential Access - T1110.003 Password Spraying
// Data Source: SigninLogs

let threshold = 5;  // Minimum distinct users targeted

SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType in ("50053", "50126")  // Locked out, Invalid credentials
| summarize 
    TargetedUsers = dcount(UserPrincipalName),
    UserList = make_set(UserPrincipalName, 20),
    Attempts = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by IPAddress, Location
| where TargetedUsers >= threshold
| extend 
    SprayDuration = LastSeen - FirstSeen,
    AttemptsPerUser = Attempts / TargetedUsers
| project 
    TimeGenerated = LastSeen,
    IPAddress,
    Location,
    TargetedUsers,
    TotalAttempts = Attempts,
    AttemptsPerUser,
    SprayDuration,
    UserList
```

### 3. Impossible Travel Detection

```kql
// Detection: Impossible Travel
// MITRE: Initial Access - T1078 Valid Accounts
// Data Source: SigninLogs

let timeWindow = 1h;
let minDistance = 500;  // km

SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == "0"  // Successful sign-ins only
| extend 
    Latitude = toreal(LocationDetails.geoCoordinates.latitude),
    Longitude = toreal(LocationDetails.geoCoordinates.longitude),
    City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion)
| where isnotempty(Latitude) and isnotempty(Longitude)
| order by UserPrincipalName, TimeGenerated asc
| serialize
| extend 
    PrevLatitude = prev(Latitude),
    PrevLongitude = prev(Longitude),
    PrevTime = prev(TimeGenerated),
    PrevCity = prev(City),
    PrevCountry = prev(Country),
    PrevUser = prev(UserPrincipalName)
| where UserPrincipalName == PrevUser
| extend 
    TimeDiff = datetime_diff('minute', TimeGenerated, PrevTime),
    // Haversine formula approximation
    Distance = geo_distance_2points(Longitude, Latitude, PrevLongitude, PrevLatitude) / 1000
| where Distance > minDistance and TimeDiff < 60  // > 500km in < 1 hour
| extend 
    RequiredSpeedKmh = Distance / (TimeDiff / 60.0)
| where RequiredSpeedKmh > 800  // Faster than commercial flight
| project 
    TimeGenerated,
    UserPrincipalName,
    CurrentLocation = strcat(City, ", ", Country),
    PreviousLocation = strcat(PrevCity, ", ", PrevCountry),
    DistanceKm = round(Distance, 0),
    TimeDiffMinutes = TimeDiff,
    RequiredSpeedKmh = round(RequiredSpeedKmh, 0),
    IPAddress
```

### 4. Suspicious Process Execution

```kql
// Detection: Suspicious Process Execution
// MITRE: Execution - T1059 Command and Scripting Interpreter
// Data Source: DeviceProcessEvents (Defender for Endpoint)

let suspiciousCommands = dynamic([
    "mimikatz", "procdump", "sekurlsa", "lsass",
    "invoke-expression", "downloadstring", "webclient",
    "encodedcommand", "bypass", "hidden", "noprofile"
]);

DeviceProcessEvents
| where TimeGenerated > ago(1d)
| where ProcessCommandLine has_any (suspiciousCommands)
    or InitiatingProcessCommandLine has_any (suspiciousCommands)
| extend 
    SuspiciousIndicators = array_length(
        set_intersect(
            split(tolower(ProcessCommandLine), " "),
            suspiciousCommands
        )
    )
| project 
    TimeGenerated,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FolderPath,
    SuspiciousIndicators
| order by SuspiciousIndicators desc
```

### 5. Anomalous Azure Activity

```kql
// Detection: Unusual Azure Resource Deletion
// MITRE: Impact - T1485 Data Destruction
// Data Source: AzureActivity

let baselineWindow = 14d;
let detectionWindow = 1d;

// Build baseline of normal deletion activity per user
let baseline = AzureActivity
| where TimeGenerated between (ago(baselineWindow) .. ago(detectionWindow))
| where OperationNameValue endswith "delete"
| where ActivityStatusValue == "Success"
| summarize 
    AvgDeletions = count() / 14.0,
    StdDev = stdev(1)
    by Caller;

// Detect anomalous deletion in recent window
AzureActivity
| where TimeGenerated > ago(detectionWindow)
| where OperationNameValue endswith "delete"
| where ActivityStatusValue == "Success"
| summarize 
    Deletions = count(),
    Resources = make_set(Resource, 10),
    ResourceTypes = make_set(ResourceProviderValue)
    by Caller, CallerIpAddress
| join kind=leftouter baseline on Caller
| extend 
    AvgDeletions = coalesce(AvgDeletions, 0.0),
    Anomaly = Deletions > (AvgDeletions + 3)  // 3x above average
| where Anomaly == true or Deletions > 5
| project 
    TimeGenerated = now(),
    User = Caller,
    SourceIP = CallerIpAddress,
    DeletionCount = Deletions,
    BaselineAverage = round(AvgDeletions, 2),
    AnomalyDetected = Anomaly,
    ResourcesDeleted = Resources,
    ResourceTypes
```

### 6. New OAuth Application Consent

```kql
// Detection: New OAuth Application Consent
// MITRE: Persistence - T1098.003 Additional Cloud Roles
// Data Source: AuditLogs

AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName == "Consent to application"
| extend 
    InitiatedBy = tostring(InitiatedBy.user.userPrincipalName),
    AppName = tostring(TargetResources[0].displayName),
    AppId = tostring(TargetResources[0].id),
    Permissions = tostring(TargetResources[0].modifiedProperties)
| extend 
    ParsedPermissions = parse_json(Permissions)
| mv-expand ParsedPermissions
| where ParsedPermissions.displayName == "ConsentAction.Permissions"
| extend 
    ConsentedPermissions = tostring(ParsedPermissions.newValue)
| project 
    TimeGenerated,
    InitiatedBy,
    AppName,
    AppId,
    ConsentedPermissions,
    IPAddress = tostring(InitiatedBy.user.ipAddress),
    UserAgent = tostring(AdditionalDetails[0].value)
// Alert on high-risk permissions
| where ConsentedPermissions has_any (
    "Mail.Read", "Mail.ReadWrite", "Files.ReadWrite.All",
    "Directory.ReadWrite.All", "User.ReadWrite.All"
)
```

### 7. Lateral Movement via RDP

```kql
// Detection: Lateral Movement via RDP
// MITRE: Lateral Movement - T1021.001 Remote Desktop Protocol
// Data Source: SecurityEvent

let knownAdmins = dynamic(["admin1", "admin2"]);

SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4624  // Successful logon
| where LogonType == 10  // RDP logon
| where AccountType == "User"
| where Account !in (knownAdmins)
| summarize 
    RDPSessions = count(),
    TargetHosts = make_set(Computer),
    TargetHostCount = dcount(Computer),
    SourceIPs = make_set(IpAddress),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Account
| where TargetHostCount > 3  // User RDP'd to more than 3 hosts
| project 
    TimeGenerated = LastSeen,
    Account,
    RDPSessionCount = RDPSessions,
    UniqueHostsAccessed = TargetHostCount,
    TargetHosts,
    SourceIPs,
    ActivityWindow = LastSeen - FirstSeen
```

---

## Best Practices

### Query Optimization

1. **Filter Early**: Apply `where` clauses before `join` or `summarize`
2. **Use Time Filters**: Always include `TimeGenerated > ago(x)`
3. **Limit Columns**: Use `project` to select only needed columns
4. **Avoid `*`**: Don't use `select *` or `project *`
5. **Use `has` over `contains`**: `has` is faster for whole-word matching

```kql
// Good - Optimized
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType != "0"
| project TimeGenerated, UserPrincipalName, IPAddress, ResultType

// Bad - Unoptimized
SigninLogs
| project *
| where ResultType != "0"
```

### Detection Rule Guidelines

| Guideline | Description |
|-----------|-------------|
| Start Conservative | Begin with high thresholds, tune down |
| Document Everything | Include comments, references, MITRE mapping |
| Test Before Deploy | Use "Test with current data" feature |
| Entity Mapping | Always map entities for investigation |
| Suppress Known-Good | Use watchlists for exclusions |
| Monitor Health | Track rule execution success/failure |

### Tuning Workflow

1. **Enable Rule**: Start with default settings
2. **Monitor Volume**: Check alert volume for 1-2 weeks
3. **Analyze False Positives**: Identify patterns in FPs
4. **Add Exclusions**: Use watchlists for known-good activity
5. **Adjust Thresholds**: Modify detection logic if needed
6. **Document Changes**: Track all tuning decisions

### Health Monitoring

```kql
// Monitor analytics rule health
SentinelHealth
| where TimeGenerated > ago(24h)
| where SentinelResourceType == "Analytics Rule"
| where Status != "Success"
| summarize 
    FailureCount = count(),
    LastFailure = max(TimeGenerated),
    FailureReasons = make_set(Description)
    by SentinelResourceName
| order by FailureCount desc
```

### Version Control and CI/CD

- Store rules as YAML/JSON in Git repository
- Use Azure DevOps or GitHub Actions for deployment
- Implement peer review for rule changes
- Test rules in dev workspace before production

---

## Resources

### Official Documentation
- [Microsoft Sentinel Documentation](https://learn.microsoft.com/en-us/azure/sentinel/)
- [KQL Reference](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

### Community Resources
- [Azure Sentinel GitHub](https://github.com/Azure/Azure-Sentinel)
- [Hunting Queries Collection](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules)
- [KQL Query Blog](https://kqlquery.com/)

### Learning
- [Must Learn KQL](https://github.com/rod-trent/MustLearnKQL)
- [SC-200 Certification](https://learn.microsoft.com/en-us/certifications/exams/sc-200)

---

## Quick Reference

### Common Result Types (SigninLogs)

| Code | Description |
|------|-------------|
| 0 | Success |
| 50053 | Account locked (Smart Lockout) |
| 50126 | Invalid username or password |
| 50074 | MFA required |
| 50076 | MFA not completed |
| 53003 | Blocked by Conditional Access |

### Windows Security Event IDs

| Event ID | Description |
|----------|-------------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4648 | Explicit credential logon |
| 4672 | Special privileges assigned |
| 4688 | Process creation |
| 4698 | Scheduled task created |
| 4720 | User account created |
| 4732 | Member added to security group |

### Logon Types

| Type | Description |
|------|-------------|
| 2 | Interactive (local) |
| 3 | Network |
| 4 | Batch |
| 5 | Service |
| 7 | Unlock |
| 8 | NetworkCleartext |
| 9 | NewCredentials |
| 10 | RemoteInteractive (RDP) |
| 11 | CachedInteractive |
