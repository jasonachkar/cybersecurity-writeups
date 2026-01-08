# KQL Detection Templates & Playbook Examples

## Table of Contents
1. [Detection Templates by Category](#detection-templates-by-category)
2. [Playbook Templates](#playbook-templates)
3. [Automation Rules](#automation-rules)
4. [Watchlist Integration](#watchlist-integration)

---

## Detection Templates by Category

### Identity-Based Detections

#### Failed MFA Attempts Followed by Success

```kql
// Detection: MFA Bypass Attempt
// MITRE: Credential Access - T1111 Multi-Factor Authentication Interception
// Description: Detects when multiple MFA failures are followed by success
// Severity: High

let mfaFailureWindow = 10m;
let mfaFailureThreshold = 3;

// Get MFA failures
let mfaFailures = SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType in ("50074", "50076", "500121")  // MFA required/not completed
| summarize 
    MFAFailures = count(),
    FailureStart = min(TimeGenerated),
    FailureEnd = max(TimeGenerated)
    by UserPrincipalName, CorrelationId;

// Get successful sign-ins after MFA
let successfulSignins = SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == "0"
| where AuthenticationRequirement == "multiFactorAuthentication";

// Correlate failures followed by success
mfaFailures
| where MFAFailures >= mfaFailureThreshold
| join kind=inner (
    successfulSignins
    | project 
        SuccessTime = TimeGenerated,
        UserPrincipalName,
        IPAddress,
        DeviceDetail,
        Location
) on UserPrincipalName
| where SuccessTime between (FailureEnd .. (FailureEnd + mfaFailureWindow))
| project 
    TimeGenerated = SuccessTime,
    UserPrincipalName,
    MFAFailuresBeforeSuccess = MFAFailures,
    TimeToSuccess = SuccessTime - FailureEnd,
    IPAddress,
    Location
```

#### Privileged Account Sign-in from New Location

```kql
// Detection: Admin Sign-in from New Location
// MITRE: Initial Access - T1078.004 Cloud Accounts
// Description: Detects privileged accounts signing in from previously unseen locations
// Severity: Medium

let lookback = 30d;
let adminUsers = dynamic(["admin@contoso.com", "globaladmin@contoso.com"]);

// Alternatively, query admin users dynamically
// let adminUsers = IdentityInfo
// | where AssignedRoles has_any ("Global Administrator", "Privileged Role Administrator")
// | distinct AccountUPN;

// Get historical locations for admin users
let historicalLocations = SigninLogs
| where TimeGenerated between (ago(lookback) .. ago(1d))
| where UserPrincipalName in (adminUsers)
| where ResultType == "0"
| distinct UserPrincipalName, tostring(LocationDetails.countryOrRegion);

// Detect new locations
SigninLogs
| where TimeGenerated > ago(1d)
| where UserPrincipalName in (adminUsers)
| where ResultType == "0"
| extend Country = tostring(LocationDetails.countryOrRegion)
| join kind=leftanti historicalLocations 
    on UserPrincipalName, $left.Country == $right.Column1
| project 
    TimeGenerated,
    UserPrincipalName,
    NewCountry = Country,
    City = tostring(LocationDetails.city),
    IPAddress,
    AppDisplayName,
    DeviceDetail
```

#### Service Principal Secret Added

```kql
// Detection: Service Principal Secret/Certificate Added
// MITRE: Persistence - T1098.001 Additional Cloud Credentials
// Description: Detects when new credentials are added to service principals
// Severity: High

AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName in (
    "Add service principal credentials",
    "Update application - Certificates and secrets management"
)
| extend 
    InitiatedByUPN = tostring(InitiatedBy.user.userPrincipalName),
    InitiatedByApp = tostring(InitiatedBy.app.displayName),
    TargetAppName = tostring(TargetResources[0].displayName),
    TargetAppId = tostring(TargetResources[0].id)
| extend 
    ModifiedProperties = TargetResources[0].modifiedProperties
| mv-expand ModifiedProperties
| where ModifiedProperties.displayName in ("KeyDescription", "FederatedIdentityCredentials")
| project 
    TimeGenerated,
    InitiatedBy = coalesce(InitiatedByUPN, InitiatedByApp),
    OperationName,
    TargetAppName,
    TargetAppId,
    CredentialType = tostring(ModifiedProperties.displayName),
    CorrelationId
```

---

### Endpoint-Based Detections

#### Living Off the Land Binaries (LOLBins)

```kql
// Detection: Suspicious LOLBin Execution
// MITRE: Defense Evasion - T1218 System Binary Proxy Execution
// Description: Detects suspicious use of legitimate Windows binaries
// Severity: Medium

let lolbins = dynamic([
    "certutil.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "wscript.exe", "cscript.exe", "msiexec.exe", "installutil.exe",
    "regasm.exe", "regsvcs.exe", "msconfig.exe", "wmic.exe",
    "msbuild.exe", "odbcconf.exe", "ieexec.exe", "cmstp.exe"
]);

let suspiciousPatterns = dynamic([
    "http://", "https://", "ftp://", "\\\\", 
    "-decode", "-urlcache", "-encode",
    "downloadstring", "downloadfile", "webclient",
    "/i:http", "scrobj.dll"
]);

DeviceProcessEvents
| where TimeGenerated > ago(1d)
| where FileName in~ (lolbins)
| where ProcessCommandLine has_any (suspiciousPatterns)
| extend 
    SuspiciousIndicators = extract_all(@"(https?://[^\s]+|\\\\[^\s]+|-decode|-encode|downloadstring|webclient)", ProcessCommandLine)
| where array_length(SuspiciousIndicators) > 0
| project 
    TimeGenerated,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FolderPath,
    SHA256,
    SuspiciousIndicators
```

#### Credential Dumping Indicators

```kql
// Detection: Credential Dumping Activity
// MITRE: Credential Access - T1003 OS Credential Dumping
// Description: Detects attempts to dump credentials from memory
// Severity: High

let credentialDumpingIndicators = dynamic([
    "sekurlsa", "logonpasswords", "lsadump", "kerberos::list",
    "procdump", "-ma lsass", "comsvcs.dll", "MiniDump",
    "ntdsutil", "vssadmin", "shadow", "ntds.dit",
    "reg save", "HKLM\\SAM", "HKLM\\SECURITY", "HKLM\\SYSTEM"
]);

union
// Process-based detection
(
    DeviceProcessEvents
    | where TimeGenerated > ago(1d)
    | where ProcessCommandLine has_any (credentialDumpingIndicators)
    | extend DetectionType = "Process Command Line"
),
// File-based detection (known tools)
(
    DeviceFileEvents
    | where TimeGenerated > ago(1d)
    | where FileName in~ ("mimikatz.exe", "procdump.exe", "gsecdump.exe", "wce.exe")
        or SHA256 in (
            "..." // Add known bad hashes
        )
    | extend DetectionType = "Known Tool File"
),
// LSASS access detection
(
    DeviceProcessEvents
    | where TimeGenerated > ago(1d)
    | where InitiatingProcessFileName !in~ ("csrss.exe", "smss.exe", "wininit.exe")
    | where FileName =~ "lsass.exe" or ProcessCommandLine contains "lsass"
    | extend DetectionType = "LSASS Access"
)
| project 
    TimeGenerated,
    DeviceName,
    AccountName,
    DetectionType,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    FolderPath
```

#### PowerShell Obfuscation Detection

```kql
// Detection: Obfuscated PowerShell
// MITRE: Defense Evasion - T1027 Obfuscated Files or Information
// Description: Detects obfuscated PowerShell commands
// Severity: Medium

DeviceProcessEvents
| where TimeGenerated > ago(1d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| extend 
    CommandLength = strlen(ProcessCommandLine),
    // Count obfuscation indicators
    BacktickCount = countof(ProcessCommandLine, "`"),
    CaretCount = countof(ProcessCommandLine, "^"),
    SpecialCharRatio = (
        countof(ProcessCommandLine, "+") +
        countof(ProcessCommandLine, "$") +
        countof(ProcessCommandLine, "{") +
        countof(ProcessCommandLine, "[")
    ) * 1.0 / CommandLength,
    // Check for encoding
    HasEncodedCommand = ProcessCommandLine has_any ("-enc", "-encodedcommand", "-e ", "-ec "),
    // Check for common bypass techniques
    HasBypass = ProcessCommandLine has_any ("-bypass", "-nop", "-noprofile", "-w hidden", "-windowstyle hidden")
| where 
    (BacktickCount > 5 and CommandLength > 100) or
    (CaretCount > 5 and CommandLength > 100) or
    (SpecialCharRatio > 0.1 and CommandLength > 200) or
    (HasEncodedCommand and HasBypass)
| project 
    TimeGenerated,
    DeviceName,
    AccountName,
    CommandLength,
    ObfuscationIndicators = pack(
        "Backticks", BacktickCount,
        "Carets", CaretCount,
        "SpecialCharRatio", round(SpecialCharRatio, 3),
        "HasEncoding", HasEncodedCommand,
        "HasBypass", HasBypass
    ),
    ProcessCommandLine,
    InitiatingProcessFileName
```

---

### Network-Based Detections

#### DNS Tunneling Detection

```kql
// Detection: Potential DNS Tunneling
// MITRE: Command and Control - T1071.004 DNS
// Description: Detects potential DNS tunneling based on query characteristics
// Severity: Medium

DnsEvents
| where TimeGenerated > ago(1d)
| where QueryType in ("TXT", "NULL", "CNAME")  // Common tunneling types
| extend 
    SubdomainLength = strlen(tostring(split(Name, ".")[0])),
    DomainDepth = array_length(split(Name, ".")),
    HasBase64Pattern = Name matches regex @"[A-Za-z0-9+/]{20,}",
    QueryLength = strlen(Name)
| where 
    SubdomainLength > 30 or
    DomainDepth > 5 or
    HasBase64Pattern or
    QueryLength > 100
| summarize 
    SuspiciousQueries = count(),
    UniqueSubdomains = dcount(tostring(split(Name, ".")[0])),
    AvgSubdomainLength = avg(SubdomainLength),
    MaxSubdomainLength = max(SubdomainLength),
    SampleQueries = make_set(Name, 5)
    by Computer, tostring(split(Name, ".")[-2]) + "." + tostring(split(Name, ".")[-1])
| where SuspiciousQueries > 50 or UniqueSubdomains > 20
| project 
    TimeGenerated = now(),
    SourceHost = Computer,
    SuspectedTunnelingDomain = Column1,
    SuspiciousQueryCount = SuspiciousQueries,
    UniqueSubdomains,
    AvgSubdomainLength = round(AvgSubdomainLength, 1),
    SampleQueries
```

#### Beaconing Detection

```kql
// Detection: C2 Beaconing Activity
// MITRE: Command and Control - T1071 Application Layer Protocol
// Description: Detects regular periodic connections indicating beaconing
// Severity: High

let minConnections = 20;
let maxJitterPercent = 15;

// For Defender for Endpoint
DeviceNetworkEvents
| where TimeGenerated > ago(1d)
| where RemoteIPType == "Public"
| where ActionType == "ConnectionSuccess"
| summarize 
    Connections = count(),
    Timestamps = make_list(TimeGenerated, 1000)
    by DeviceName, RemoteIP, RemoteUrl, RemotePort
| where Connections >= minConnections
| mv-apply Timestamps to typeof(datetime) on (
    order by Timestamps asc
    | extend 
        PrevTimestamp = prev(Timestamps),
        Interval = datetime_diff('second', Timestamps, prev(Timestamps))
    | where isnotnull(PrevTimestamp)
    | summarize 
        AvgInterval = avg(Interval),
        StdDevInterval = stdev(Interval),
        MinInterval = min(Interval),
        MaxInterval = max(Interval)
)
| extend 
    JitterPercent = (StdDevInterval / AvgInterval) * 100
| where JitterPercent < maxJitterPercent  // Low jitter = regular beaconing
| where AvgInterval between (10 .. 3600)  // 10 seconds to 1 hour intervals
| project 
    TimeGenerated = now(),
    DeviceName,
    RemoteIP,
    RemoteUrl,
    RemotePort,
    ConnectionCount = Connections,
    AvgIntervalSeconds = round(AvgInterval, 0),
    JitterPercent = round(JitterPercent, 1),
    BeaconingScore = 100 - JitterPercent
| order by BeaconingScore desc
```

---

### Cloud-Based Detections

#### Suspicious Azure Resource Deployment

```kql
// Detection: Cryptocurrency Mining Resource Deployment
// MITRE: Impact - T1496 Resource Hijacking
// Description: Detects deployment of high-compute resources potentially for mining
// Severity: High

AzureActivity
| where TimeGenerated > ago(1d)
| where OperationNameValue has "Microsoft.Compute/virtualMachines/write"
| where ActivityStatusValue == "Success"
| extend 
    ResourceDetails = parse_json(Properties)
| extend 
    VMSize = tostring(ResourceDetails.responseBody.properties.hardwareProfile.vmSize),
    Location = tostring(ResourceDetails.responseBody.location)
| where VMSize has_any (
    "Standard_NC", "Standard_ND", "Standard_NV",  // GPU VMs
    "Standard_H", "Standard_HB", "Standard_HC",    // High-performance compute
    "Standard_F72", "Standard_F64", "Standard_E64" // Large compute
)
// Check for unusual deployment patterns
| summarize 
    DeploymentCount = count(),
    VMSizes = make_set(VMSize),
    Locations = make_set(Location),
    ResourceGroups = make_set(ResourceGroup)
    by Caller, CallerIpAddress, bin(TimeGenerated, 1h)
| where DeploymentCount > 3  // Multiple high-compute VMs in 1 hour
| project 
    TimeGenerated,
    DeployedBy = Caller,
    SourceIP = CallerIpAddress,
    HighComputeVMsDeployed = DeploymentCount,
    VMSizes,
    Locations,
    ResourceGroups
```

#### Storage Account Anonymous Access Enabled

```kql
// Detection: Storage Account Public Access Enabled
// MITRE: Defense Evasion - T1562 Impair Defenses
// Description: Detects when storage accounts are configured for public access
// Severity: High

AzureActivity
| where TimeGenerated > ago(1d)
| where OperationNameValue == "Microsoft.Storage/storageAccounts/write"
| where ActivityStatusValue == "Success"
| extend 
    Properties = parse_json(Properties_d)
| extend 
    AllowBlobPublicAccess = tostring(Properties.requestbody.properties.allowBlobPublicAccess),
    PublicNetworkAccess = tostring(Properties.requestbody.properties.publicNetworkAccess)
| where AllowBlobPublicAccess == "true" or PublicNetworkAccess == "Enabled"
| project 
    TimeGenerated,
    StorageAccount = Resource,
    ResourceGroup,
    ModifiedBy = Caller,
    SourceIP = CallerIpAddress,
    AllowBlobPublicAccess,
    PublicNetworkAccess,
    SubscriptionId
```

---

## Playbook Templates

### Incident Enrichment Playbook

```json
{
    "definition": {
        "triggers": {
            "Microsoft_Sentinel_incident": {
                "type": "ApiConnectionWebhook",
                "inputs": {
                    "host": {
                        "connection": {
                            "name": "@parameters('$connections')['azuresentinel']['connectionId']"
                        }
                    },
                    "body": {
                        "callback_url": "@listCallbackUrl()"
                    },
                    "path": "/incident-creation"
                }
            }
        },
        "actions": {
            "Get_incident": {
                "type": "ApiConnection",
                "inputs": {
                    "host": {
                        "connection": {
                            "name": "@parameters('$connections')['azuresentinel']['connectionId']"
                        }
                    },
                    "method": "get",
                    "path": "/incidents/@{encodeURIComponent(triggerBody()?['properties']?['id'])}"
                }
            },
            "For_each_IP_entity": {
                "type": "Foreach",
                "foreach": "@body('Get_incident')?['properties']?['relatedEntities']",
                "actions": {
                    "Condition_Is_IP": {
                        "type": "If",
                        "expression": {
                            "equals": ["@items('For_each_IP_entity')?['kind']", "Ip"]
                        },
                        "actions": {
                            "Get_IP_reputation": {
                                "type": "Http",
                                "inputs": {
                                    "method": "GET",
                                    "uri": "https://api.abuseipdb.com/api/v2/check",
                                    "headers": {
                                        "Key": "@parameters('AbuseIPDB_ApiKey')"
                                    },
                                    "queries": {
                                        "ipAddress": "@items('For_each_IP_entity')?['properties']?['address']"
                                    }
                                }
                            },
                            "Add_comment_with_IP_intel": {
                                "type": "ApiConnection",
                                "inputs": {
                                    "host": {
                                        "connection": {
                                            "name": "@parameters('$connections')['azuresentinel']['connectionId']"
                                        }
                                    },
                                    "method": "post",
                                    "path": "/incidents/@{encodeURIComponent(triggerBody()?['properties']?['id'])}/comments",
                                    "body": {
                                        "message": "IP Enrichment: @{items('For_each_IP_entity')?['properties']?['address']}\nAbuse Score: @{body('Get_IP_reputation')?['data']?['abuseConfidenceScore']}\nCountry: @{body('Get_IP_reputation')?['data']?['countryCode']}"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
```

### User Containment Playbook

```json
{
    "description": "Disable compromised user account and revoke sessions",
    "actions": [
        {
            "name": "Get_User_Details",
            "type": "Microsoft Graph",
            "action": "GET /users/{userPrincipalName}"
        },
        {
            "name": "Disable_User_Account",
            "type": "Microsoft Graph",
            "action": "PATCH /users/{userPrincipalName}",
            "body": {
                "accountEnabled": false
            }
        },
        {
            "name": "Revoke_User_Sessions",
            "type": "Microsoft Graph",
            "action": "POST /users/{userPrincipalName}/revokeSignInSessions"
        },
        {
            "name": "Send_Teams_Notification",
            "type": "Microsoft Teams",
            "action": "Post message to channel",
            "body": {
                "text": "🚨 User Containment Alert\n\nUser: {userPrincipalName}\nAction: Account disabled and sessions revoked\nIncident: {incidentId}\nTime: {timestamp}"
            }
        },
        {
            "name": "Update_Incident",
            "type": "Azure Sentinel",
            "action": "Add comment",
            "body": {
                "message": "Automated Response: User account disabled and sessions revoked."
            }
        }
    ]
}
```

---

## Automation Rules

### Auto-Assign High Severity Incidents

```json
{
    "name": "Auto-assign Critical Incidents",
    "triggerType": "IncidentCreated",
    "conditions": [
        {
            "property": "Severity",
            "operator": "Equals",
            "values": ["High"]
        }
    ],
    "actions": [
        {
            "actionType": "ModifyProperties",
            "properties": {
                "owner": "soc-tier2@contoso.com",
                "status": "Active"
            }
        },
        {
            "actionType": "RunPlaybook",
            "playbookResourceId": "/subscriptions/.../playbooks/Enrich-Incident"
        }
    ]
}
```

### Auto-Close Known False Positives

```json
{
    "name": "Auto-close Approved Scanning",
    "triggerType": "IncidentCreated",
    "conditions": [
        {
            "property": "Title",
            "operator": "Contains",
            "values": ["Vulnerability Scan Detected"]
        },
        {
            "property": "Entities:IP",
            "operator": "InWatchlist",
            "watchlistName": "ApprovedScanners"
        }
    ],
    "actions": [
        {
            "actionType": "ModifyProperties",
            "properties": {
                "status": "Closed",
                "classification": "BenignPositive",
                "classificationReason": "ConfirmedActivity"
            }
        },
        {
            "actionType": "AddComment",
            "comment": "Auto-closed: Source IP is an approved vulnerability scanner."
        }
    ]
}
```

---

## Watchlist Integration

### Creating a Watchlist for VIP Users

```kql
// Query to populate VIP users watchlist
IdentityInfo
| where AssignedRoles has_any ("Global Administrator", "Security Administrator", "Exchange Administrator")
| union (
    // Add C-level executives
    IdentityInfo
    | where JobTitle has_any ("CEO", "CFO", "CTO", "CISO", "COO")
)
| distinct 
    UserPrincipalName,
    DisplayName,
    JobTitle,
    Department = Department,
    VIPReason = case(
        AssignedRoles has "Global Administrator", "Global Admin",
        JobTitle has "CEO", "Executive",
        "High-Value User"
    )
```

### Using Watchlist in Detection

```kql
// Detection using VIP watchlist
let VIPUsers = _GetWatchlist('VIPUsers')
| project UserPrincipalName;

SigninLogs
| where TimeGenerated > ago(1d)
| where UserPrincipalName in (VIPUsers)
| where ResultType != "0"  // Failed sign-ins
| summarize 
    FailedAttempts = count(),
    SourceIPs = make_set(IPAddress),
    Locations = make_set(Location)
    by UserPrincipalName
| where FailedAttempts > 5
| project 
    TimeGenerated = now(),
    VIPUser = UserPrincipalName,
    FailedLoginAttempts = FailedAttempts,
    SourceIPs,
    Locations
```

### IP Allow/Block Lists

```kql
// Using IP watchlist for exclusions
let AllowedIPs = _GetWatchlist('AllowedIPs')
| project IPAddress;

let BlockedIPs = _GetWatchlist('BlockedIPs')
| project IPAddress;

SigninLogs
| where TimeGenerated > ago(1d)
| where IPAddress !in (AllowedIPs)  // Exclude known-good
| where IPAddress in (BlockedIPs)   // Focus on known-bad
| project 
    TimeGenerated,
    UserPrincipalName,
    BlockedIPAddress = IPAddress,
    Location,
    AppDisplayName
```

---

## Detection Development Checklist

- [ ] **Define Objective**: What attack/behavior are you detecting?
- [ ] **Map to MITRE**: Identify tactics, techniques, sub-techniques
- [ ] **Identify Data Sources**: Which tables contain relevant data?
- [ ] **Write Initial Query**: Start with broad detection
- [ ] **Test with Historical Data**: Validate detection works
- [ ] **Tune for False Positives**: Add exclusions, adjust thresholds
- [ ] **Configure Entity Mapping**: Map accounts, hosts, IPs
- [ ] **Set Severity**: Based on impact and confidence
- [ ] **Add Documentation**: Description, references, response steps
- [ ] **Create Automation**: Playbooks for enrichment/response
- [ ] **Deploy to Production**: Enable rule with monitoring
- [ ] **Review and Iterate**: Regular tuning based on feedback
