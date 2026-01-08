# Azure Landing Zone Security

A comprehensive guide to designing and implementing secure Azure Landing Zones following Microsoft's Cloud Adoption Framework best practices.

## Table of Contents

1. [Introduction to Azure Landing Zones](#introduction-to-azure-landing-zones)
2. [Architecture Overview](#architecture-overview)
3. [Management Group Hierarchy](#management-group-hierarchy)
4. [Identity and Access Management](#identity-and-access-management)
5. [Network Security](#network-security)
6. [Azure Policy and Governance](#azure-policy-and-governance)
7. [Microsoft Defender for Cloud](#microsoft-defender-for-cloud)
8. [Zero Trust Implementation](#zero-trust-implementation)
9. [Subscription Vending](#subscription-vending)
10. [Monitoring and Logging](#monitoring-and-logging)
11. [Security Checklists](#security-checklists)

---

## Introduction to Azure Landing Zones

### What is an Azure Landing Zone?

An Azure Landing Zone is a scalable, modular environment that follows Microsoft's best practices for governance, security, and operations. It provides the foundation upon which organizations deploy and manage their Azure workloads.

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Azure Landing Zone Architecture                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  PLATFORM LANDING ZONE (Shared Services)                            │
│  ├─ Identity Subscription (AD DS, DNS, identity services)           │
│  ├─ Management Subscription (Log Analytics, Automation, Sentinel)   │
│  └─ Connectivity Subscription (Hub VNet, Firewall, VPN/ExpressRoute)│
│                                                                      │
│  APPLICATION LANDING ZONES (Workload Environments)                  │
│  ├─ Corp Landing Zones (Internal apps, private connectivity)        │
│  └─ Online Landing Zones (Internet-facing apps)                     │
│                                                                      │
│  GOVERNANCE FOUNDATION                                               │
│  ├─ Management Group Hierarchy                                      │
│  ├─ Azure Policy Assignments                                        │
│  ├─ RBAC Role Assignments                                           │
│  └─ Resource Tagging Standards                                      │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Eight Design Areas

| Design Area | Security Focus |
|-------------|----------------|
| **Azure Billing & Tenant** | Tenant security, billing account access |
| **Identity & Access Management** | Authentication, authorization, privileged access |
| **Management Group & Subscription** | Hierarchy design, policy inheritance |
| **Network Topology & Connectivity** | Hub-spoke, segmentation, private connectivity |
| **Security** | Defense in depth, threat protection |
| **Management** | Monitoring, patching, backup |
| **Governance** | Policy enforcement, compliance |
| **Platform Automation & DevOps** | IaC security, CI/CD pipelines |

### Key Design Principles

1. **Subscription Democratization**: Enable application teams with pre-configured subscriptions
2. **Policy-Driven Governance**: Use Azure Policy for automated guardrails
3. **Single Control and Management Plane**: Unified operations across all landing zones
4. **Application-Centric Service Model**: Align subscriptions to workloads
5. **Enterprise-Scale Architecture**: Design for growth and evolution

---

## Architecture Overview

### Reference Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         AZURE LANDING ZONE REFERENCE                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                    ROOT MANAGEMENT GROUP (Tenant)                     │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│  ┌─────────────────────────────────┴─────────────────────────────────┐      │
│  │               INTERMEDIATE ROOT (e.g., "Contoso")                  │      │
│  │  Policies: Security baseline, MCSB, allowed regions               │      │
│  └─────────────────────────────────┬─────────────────────────────────┘      │
│                                    │                                         │
│     ┌──────────────────────────────┼──────────────────────────────┐         │
│     │                              │                              │          │
│     ▼                              ▼                              ▼          │
│  ┌──────────┐               ┌────────────┐               ┌────────────┐     │
│  │ Platform │               │ Landing    │               │ Decomm-    │     │
│  │          │               │ Zones      │               │ issioned   │     │
│  └────┬─────┘               └─────┬──────┘               └────────────┘     │
│       │                           │                                          │
│  ┌────┴────┐                 ┌────┴────┐                                    │
│  │         │                 │         │                                    │
│  ▼         ▼                 ▼         ▼                                    │
│ ┌───┐ ┌───┐ ┌───┐         ┌────┐   ┌────────┐                              │
│ │Mgt│ │Con│ │Idn│         │Corp│   │ Online │                              │
│ └───┘ └───┘ └───┘         └────┘   └────────┘                              │
│   │     │     │              │          │                                   │
│   ▼     ▼     ▼              ▼          ▼                                   │
│ [Log] [Hub] [AD]          [App1]    [App2]                                 │
│ [Snl] [FW]  [DNS]         [App3]    [App4]                                 │
│ [Auto][VPN]               (Corp     (Internet-                             │
│       [ER]                 Apps)     facing)                               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Platform vs Application Landing Zones

| Aspect | Platform Landing Zone | Application Landing Zone |
|--------|----------------------|--------------------------|
| **Purpose** | Shared services | Workload hosting |
| **Ownership** | Platform team | Application team |
| **Examples** | Identity, Connectivity, Management | Line-of-business apps |
| **Subscriptions** | 3 (Identity, Management, Connectivity) | 1+ per workload |
| **Policy** | Defines baseline | Inherits + extends |
| **Network** | Hub VNet, Firewall | Spoke VNets |

---

## Management Group Hierarchy

### Recommended Structure

```
Tenant Root Group
└── Contoso (Intermediate Root)
    ├── Platform
    │   ├── Identity
    │   │   └── Identity Subscription
    │   ├── Management
    │   │   └── Management Subscription
    │   └── Connectivity
    │       └── Connectivity Subscription
    ├── Landing Zones
    │   ├── Corp
    │   │   ├── HR App Subscription
    │   │   ├── Finance App Subscription
    │   │   └── ...
    │   ├── Online
    │   │   ├── E-commerce Subscription
    │   │   ├── Public Website Subscription
    │   │   └── ...
    │   └── Confidential (Custom archetype)
    │       └── High-security workloads
    ├── Sandbox
    │   └── Development/Testing Subscriptions
    └── Decommissioned
        └── Retired Subscriptions
```

### Policy Assignment Strategy

| Management Group | Key Policies |
|-----------------|--------------|
| **Intermediate Root** | Microsoft Cloud Security Benchmark (MCSB), Allowed regions, Required tags, Audit diagnostic settings |
| **Platform** | Platform-specific security controls |
| **Landing Zones** | Application baseline policies |
| **Corp** | Private endpoint enforcement, No public IPs |
| **Online** | WAF requirement, DDoS protection |
| **Sandbox** | Relaxed policies for experimentation |

---

## Identity and Access Management

### Microsoft Entra ID Integration

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Identity Architecture                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ON-PREMISES                           AZURE                         │
│  ┌─────────────┐                      ┌──────────────────┐          │
│  │ Active      │ ←── Entra Connect ──→│ Microsoft        │          │
│  │ Directory   │     Cloud Sync       │ Entra ID         │          │
│  │ Domain      │                      │                  │          │
│  │ Services    │                      │ ├─ Users         │          │
│  └─────────────┘                      │ ├─ Groups        │          │
│        │                              │ ├─ App Regs      │          │
│        │                              │ └─ Service       │          │
│        ▼                              │   Principals     │          │
│  ┌─────────────┐                      └────────┬─────────┘          │
│  │ Defender    │                               │                    │
│  │ for         │                               ▼                    │
│  │ Identity    │                      ┌──────────────────┐          │
│  │ Sensors     │                      │ Azure Resources  │          │
│  └─────────────┘                      │                  │          │
│                                       │ ├─ Subscriptions │          │
│                                       │ ├─ Resource Grps │          │
│                                       │ └─ Resources     │          │
│                                       └──────────────────┘          │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### RBAC Best Practices

```bicep
// Example: Custom Role Definition for Landing Zone Owner
resource landingZoneOwnerRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid('landing-zone-owner', subscription().id)
  properties: {
    roleName: 'Landing Zone Owner'
    description: 'Can manage resources within landing zone but not RBAC or networking'
    type: 'CustomRole'
    permissions: [
      {
        actions: [
          '*'
        ]
        notActions: [
          'Microsoft.Authorization/*/Delete'
          'Microsoft.Authorization/*/Write'
          'Microsoft.Authorization/elevateAccess/Action'
          'Microsoft.Network/virtualNetworks/subnets/join/action'
          'Microsoft.Network/virtualNetworks/peer/action'
        ]
        dataActions: []
        notDataActions: []
      }
    ]
    assignableScopes: [
      subscription().id
    ]
  }
}
```

### Privileged Identity Management (PIM)

| Configuration | Recommendation |
|--------------|----------------|
| **Activation Duration** | 8 hours maximum for standard roles |
| **Justification** | Required for all activations |
| **MFA** | Required for activation |
| **Approval** | Required for Global Admin, Security Admin |
| **Notification** | Enabled for all role activations |
| **Access Reviews** | Quarterly for all privileged roles |

### Conditional Access Policies

```json
{
  "displayName": "Require MFA for Azure Management",
  "state": "enabled",
  "conditions": {
    "applications": {
      "includeApplications": [
        "797f4846-ba00-4fd7-ba43-dac1f8f63013"  // Azure Management
      ]
    },
    "users": {
      "includeUsers": ["All"],
      "excludeUsers": ["BreakGlassAccounts"]
    },
    "locations": {
      "includeLocations": ["All"],
      "excludeLocations": ["AllTrusted"]
    }
  },
  "grantControls": {
    "operator": "AND",
    "builtInControls": [
      "mfa",
      "compliantDevice"
    ]
  },
  "sessionControls": {
    "signInFrequency": {
      "value": 4,
      "type": "hours"
    }
  }
}
```

---

## Network Security

### Hub-Spoke Topology

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         HUB-SPOKE NETWORK ARCHITECTURE                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                           ┌─────────────────┐                               │
│                           │   ON-PREMISES   │                               │
│                           │    DATACENTER   │                               │
│                           └────────┬────────┘                               │
│                                    │                                         │
│                           ExpressRoute / VPN                                │
│                                    │                                         │
│  ┌─────────────────────────────────┴─────────────────────────────────────┐  │
│  │                         HUB VNET (10.0.0.0/16)                         │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │ Gateway Subnet (10.0.0.0/27)                                    │  │  │
│  │  │ ├─ VPN Gateway                                                  │  │  │
│  │  │ └─ ExpressRoute Gateway                                         │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │ AzureFirewallSubnet (10.0.1.0/26)                               │  │  │
│  │  │ └─ Azure Firewall (Premium)                                     │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │ AzureBastionSubnet (10.0.2.0/26)                                │  │  │
│  │  │ └─ Azure Bastion                                                │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │ DNS Subnet (10.0.3.0/28)                                        │  │  │
│  │  │ └─ DNS Private Resolver                                         │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────┬──────────────────────────────────────┘  │
│                                   │                                          │
│              ┌────────────────────┼────────────────────┐                    │
│              │                    │                    │                    │
│              ▼                    ▼                    ▼                    │
│  ┌───────────────────┐ ┌───────────────────┐ ┌───────────────────┐         │
│  │ SPOKE 1 (Corp)    │ │ SPOKE 2 (Online)  │ │ SPOKE 3 (Data)    │         │
│  │ 10.1.0.0/16       │ │ 10.2.0.0/16       │ │ 10.3.0.0/16       │         │
│  │                   │ │                   │ │                   │         │
│  │ ├─ Web Subnet     │ │ ├─ App Gateway    │ │ ├─ AKS Subnet     │         │
│  │ ├─ App Subnet     │ │ ├─ Web Subnet     │ │ ├─ SQL Subnet     │         │
│  │ ├─ DB Subnet      │ │ └─ Private EP     │ │ └─ Private EP     │         │
│  │ └─ Private EP     │ │                   │ │                   │         │
│  └───────────────────┘ └───────────────────┘ └───────────────────┘         │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Azure Firewall Configuration

```bicep
// Azure Firewall Policy with Premium features
resource firewallPolicy 'Microsoft.Network/firewallPolicies@2023-05-01' = {
  name: 'hub-firewall-policy'
  location: location
  properties: {
    sku: {
      tier: 'Premium'
    }
    threatIntelMode: 'Deny'
    threatIntelWhitelist: {
      fqdns: []
      ipAddresses: []
    }
    dnsSettings: {
      enableProxy: true
      servers: []
    }
    intrusionDetection: {
      mode: 'Deny'
      configuration: {
        signatureOverrides: []
        bypassTrafficSettings: []
      }
    }
    transportSecurity: {
      certificateAuthority: {
        name: 'tls-inspection-ca'
        keyVaultSecretId: keyVaultCertSecretId
      }
    }
  }
}

// Network Rule Collection - Spoke to Spoke
resource networkRules 'Microsoft.Network/firewallPolicies/ruleCollectionGroups@2023-05-01' = {
  parent: firewallPolicy
  name: 'DefaultNetworkRuleCollectionGroup'
  properties: {
    priority: 200
    ruleCollections: [
      {
        ruleCollectionType: 'FirewallPolicyFilterRuleCollection'
        name: 'AllowSpokeToSpoke'
        priority: 100
        action: {
          type: 'Allow'
        }
        rules: [
          {
            ruleType: 'NetworkRule'
            name: 'CorpToData'
            sourceAddresses: ['10.1.0.0/16']
            destinationAddresses: ['10.3.0.0/16']
            destinationPorts: ['443', '1433']
            ipProtocols: ['TCP']
          }
        ]
      }
    ]
  }
}
```

### Network Security Groups (NSGs)

```bicep
// NSG for Web Tier
resource webNsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'nsg-web-tier'
  location: location
  properties: {
    securityRules: [
      {
        name: 'AllowHTTPSInbound'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: 'Internet'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '443'
        }
      }
      {
        name: 'AllowAzureLoadBalancer'
        properties: {
          priority: 110
          direction: 'Inbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefix: 'AzureLoadBalancer'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
      {
        name: 'DenyAllInbound'
        properties: {
          priority: 4096
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
    ]
  }
}
```

### Private Endpoints Strategy

| Service Type | Private Endpoint Zone | Hub/Spoke Placement |
|--------------|----------------------|---------------------|
| Storage Blob | privatelink.blob.core.windows.net | Spoke (workload) |
| SQL Database | privatelink.database.windows.net | Spoke (workload) |
| Key Vault | privatelink.vaultcore.azure.net | Spoke (workload) |
| Container Registry | privatelink.azurecr.io | Hub (shared) |
| Log Analytics | privatelink.ods.opinsights.azure.net | Hub (management) |

---

## Azure Policy and Governance

### ALZ Default Policy Initiatives

| Initiative | Management Group | Purpose |
|------------|-----------------|---------|
| **Microsoft Cloud Security Benchmark** | Intermediate Root | Baseline security controls |
| **Configure Defender for Cloud** | Intermediate Root | Enable all Defender plans |
| **Deploy Diagnostic Settings** | Intermediate Root | Central logging |
| **Deny Public IP** | Corp | Enforce private connectivity |
| **Deploy Private DNS Zones** | Connectivity | Private endpoint resolution |
| **Enforce TLS 1.2** | Landing Zones | Secure communications |

### Custom Policy Examples

```json
// Policy: Require TLS 1.2 for Storage Accounts
{
  "mode": "All",
  "policyRule": {
    "if": {
      "allOf": [
        {
          "field": "type",
          "equals": "Microsoft.Storage/storageAccounts"
        },
        {
          "field": "Microsoft.Storage/storageAccounts/minimumTlsVersion",
          "notEquals": "TLS1_2"
        }
      ]
    },
    "then": {
      "effect": "deny"
    }
  }
}
```

```json
// Policy: Deny Public Network Access for Key Vault
{
  "mode": "All",
  "policyRule": {
    "if": {
      "allOf": [
        {
          "field": "type",
          "equals": "Microsoft.KeyVault/vaults"
        },
        {
          "field": "Microsoft.KeyVault/vaults/publicNetworkAccess",
          "notEquals": "Disabled"
        }
      ]
    },
    "then": {
      "effect": "deny"
    }
  }
}
```

```json
// Policy: Deploy Defender for Storage (DeployIfNotExists)
{
  "mode": "All",
  "policyRule": {
    "if": {
      "field": "type",
      "equals": "Microsoft.Storage/storageAccounts"
    },
    "then": {
      "effect": "deployIfNotExists",
      "details": {
        "type": "Microsoft.Security/defenderForStorageSettings",
        "name": "current",
        "existenceCondition": {
          "field": "Microsoft.Security/defenderForStorageSettings/isEnabled",
          "equals": true
        },
        "roleDefinitionIds": [
          "/providers/Microsoft.Authorization/roleDefinitions/17d1049b-9a84-46fb-8f53-869881c3d3ab"
        ],
        "deployment": {
          "properties": {
            "mode": "incremental",
            "template": {
              "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
              "contentVersion": "1.0.0.0",
              "resources": [
                {
                  "type": "Microsoft.Security/defenderForStorageSettings",
                  "apiVersion": "2022-12-01-preview",
                  "name": "current",
                  "properties": {
                    "isEnabled": true,
                    "malwareScanning": {
                      "onUpload": {
                        "isEnabled": true,
                        "capGBPerMonth": 5000
                      }
                    },
                    "sensitiveDataDiscovery": {
                      "isEnabled": true
                    }
                  }
                }
              ]
            }
          }
        }
      }
    }
  }
}
```

### Policy Enforcement Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Policy Enforcement Flow                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. DEPLOYMENT REQUEST                                              │
│     └─ ARM/Bicep/Terraform deployment initiated                     │
│                                                                      │
│  2. POLICY EVALUATION                                               │
│     ├─ Inherited policies from parent management groups             │
│     ├─ Policies assigned at subscription level                      │
│     └─ Policies assigned at resource group level                    │
│                                                                      │
│  3. POLICY EFFECTS                                                  │
│     ├─ Deny → Block non-compliant resources                        │
│     ├─ Audit → Log non-compliance, allow deployment                │
│     ├─ Modify → Auto-remediate configuration                       │
│     ├─ DeployIfNotExists → Deploy required configurations          │
│     ├─ Append → Add tags or properties                             │
│     └─ AuditIfNotExists → Audit missing related resources          │
│                                                                      │
│  4. COMPLIANCE REPORTING                                            │
│     ├─ Policy compliance dashboard                                  │
│     ├─ Microsoft Defender for Cloud regulatory compliance           │
│     └─ Azure Resource Graph queries                                 │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Microsoft Defender for Cloud

### Defender Plans for Landing Zones

| Defender Plan | Target Resources | Key Features |
|--------------|------------------|--------------|
| **Defender for Servers** | VMs, Arc servers | Vulnerability assessment, EDR, JIT access |
| **Defender for Containers** | AKS, ACR, Arc K8s | Runtime protection, image scanning |
| **Defender for SQL** | Azure SQL, SQL on VMs | Threat detection, vulnerability assessment |
| **Defender for Storage** | Storage accounts | Malware scanning, sensitive data discovery |
| **Defender for Key Vault** | Key Vaults | Unusual access detection |
| **Defender for App Service** | Web Apps, Functions | Threat detection, vulnerability assessment |
| **Defender for DNS** | DNS queries | Malicious domain detection |
| **Defender CSPM** | All resources | Attack path analysis, cloud security graph |

### Defender for Cloud Configuration

```bicep
// Enable Defender for Cloud at subscription level
resource defenderForServers 'Microsoft.Security/pricings@2023-01-01' = {
  name: 'VirtualMachines'
  properties: {
    pricingTier: 'Standard'
    subPlan: 'P2'  // Plan 2 includes Defender for Endpoint
    extensions: [
      {
        name: 'MdeDesignatedSubscription'
        isEnabled: 'True'
      }
      {
        name: 'AgentlessVmScanning'
        isEnabled: 'True'
      }
    ]
  }
}

resource defenderForContainers 'Microsoft.Security/pricings@2023-01-01' = {
  name: 'Containers'
  properties: {
    pricingTier: 'Standard'
    extensions: [
      {
        name: 'ContainerRegistriesVulnerabilityAssessments'
        isEnabled: 'True'
      }
    ]
  }
}

resource defenderForStorage 'Microsoft.Security/pricings@2023-01-01' = {
  name: 'StorageAccounts'
  properties: {
    pricingTier: 'Standard'
    subPlan: 'DefenderForStorageV2'
    extensions: [
      {
        name: 'OnUploadMalwareScanning'
        isEnabled: 'True'
        additionalExtensionProperties: {
          CapGBPerMonthPerStorageAccount: '5000'
        }
      }
      {
        name: 'SensitiveDataDiscovery'
        isEnabled: 'True'
      }
    ]
  }
}
```

### Security Contact Configuration

```bicep
resource securityContacts 'Microsoft.Security/securityContacts@2020-01-01-preview' = {
  name: 'default'
  properties: {
    emails: 'security-team@contoso.com'
    phone: '+1-555-555-5555'
    alertNotifications: {
      state: 'On'
      minimalSeverity: 'Medium'
    }
    notificationsByRole: {
      state: 'On'
      roles: ['Owner', 'Contributor']
    }
  }
}
```

---

## Zero Trust Implementation

### Zero Trust Pillars in Landing Zones

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Zero Trust in Azure Landing Zones                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  IDENTITY PILLAR                                                    │
│  ├─ Microsoft Entra ID as primary IdP                               │
│  ├─ Conditional Access policies                                     │
│  ├─ PIM for privileged access                                       │
│  ├─ Managed identities for workloads                                │
│  └─ Separate admin accounts (cloud-only)                            │
│                                                                      │
│  ENDPOINTS PILLAR                                                   │
│  ├─ Microsoft Intune for device management                          │
│  ├─ Defender for Endpoint on all servers                            │
│  ├─ Compliant device requirement                                    │
│  └─ Azure Virtual Desktop with conditional access                   │
│                                                                      │
│  NETWORK PILLAR                                                     │
│  ├─ Micro-segmentation with NSGs                                    │
│  ├─ Private endpoints for all PaaS                                  │
│  ├─ Azure Firewall for traffic inspection                           │
│  ├─ No public IPs for Corp workloads                                │
│  └─ TLS 1.2+ enforcement                                            │
│                                                                      │
│  DATA PILLAR                                                        │
│  ├─ Encryption at rest (CMK where required)                         │
│  ├─ Encryption in transit                                           │
│  ├─ Microsoft Purview for data governance                           │
│  └─ Azure Information Protection                                    │
│                                                                      │
│  APPLICATIONS PILLAR                                                │
│  ├─ Application Gateway with WAF                                    │
│  ├─ API Management for API security                                 │
│  ├─ Defender for App Service                                        │
│  └─ Container security scanning                                     │
│                                                                      │
│  INFRASTRUCTURE PILLAR                                              │
│  ├─ Just-in-time VM access                                          │
│  ├─ Azure Bastion for secure RDP/SSH                                │
│  ├─ Azure Policy guardrails                                         │
│  └─ Infrastructure-as-Code validation                               │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Implementation Mapping

| Zero Trust Principle | Landing Zone Implementation |
|---------------------|----------------------------|
| **Verify explicitly** | Conditional Access, MFA everywhere, Managed identities |
| **Least privilege access** | RBAC, PIM, JIT, custom roles |
| **Assume breach** | Network segmentation, Defender XDR, Sentinel SIEM |

---

## Subscription Vending

### Subscription Vending Process

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Subscription Vending Workflow                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. REQUEST                                                         │
│     ├─ Application team submits request                             │
│     ├─ ServiceNow / Forms / Custom portal                           │
│     └─ Captures: Owner, budget, workload type, network needs        │
│                                                                      │
│  2. APPROVAL                                                        │
│     ├─ Platform team reviews request                                │
│     ├─ Budget approval                                              │
│     └─ Security classification validation                           │
│                                                                      │
│  3. PROVISIONING (Automated via IaC)                                │
│     ├─ Create subscription (Bicep/Terraform module)                 │
│     ├─ Move to appropriate management group                         │
│     ├─ Apply tags (cost center, owner, environment)                 │
│     ├─ Assign RBAC roles                                            │
│     ├─ Create spoke VNet and peer to hub                            │
│     ├─ Configure DNS settings                                       │
│     └─ Create budget alerts                                         │
│                                                                      │
│  4. HANDOVER                                                        │
│     ├─ Notify application team                                      │
│     ├─ Provide documentation                                        │
│     └─ Schedule onboarding session                                  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Terraform Subscription Vending Example

```hcl
# Subscription vending with Terraform
module "subscription_vending" {
  source  = "Azure/lz-vending/azurerm"
  version = "~> 4.0"

  # Subscription creation
  subscription_alias_enabled = true
  subscription_billing_scope = "/providers/Microsoft.Billing/billingAccounts/xxx/enrollmentAccounts/xxx"
  subscription_display_name  = "sub-${var.workload_name}-${var.environment}"
  subscription_alias_name    = "sub-${var.workload_name}-${var.environment}"
  subscription_workload      = var.environment == "prod" ? "Production" : "DevTest"

  # Management group placement
  subscription_management_group_association_enabled = true
  subscription_management_group_id = var.workload_type == "corp" ? (
    "/providers/Microsoft.Management/managementGroups/mg-corp"
  ) : "/providers/Microsoft.Management/managementGroups/mg-online"

  # Tags
  subscription_tags = {
    workload      = var.workload_name
    environment   = var.environment
    costCenter    = var.cost_center
    owner         = var.owner_email
    createdBy     = "subscription-vending"
    createdDate   = timestamp()
  }

  # RBAC assignments
  role_assignment_enabled = true
  role_assignments = {
    owner = {
      principal_id   = var.owner_group_id
      definition     = "Owner"
      relative_scope = ""
    }
    reader = {
      principal_id   = var.security_group_id
      definition     = "Reader"
      relative_scope = ""
    }
  }

  # Network configuration
  virtual_network_enabled = true
  virtual_networks = {
    spoke = {
      name                    = "vnet-${var.workload_name}-${var.location}"
      address_space           = [var.address_space]
      resource_group_name     = "rg-networking-${var.workload_name}"
      location                = var.location
      
      hub_peering_enabled                     = true
      hub_network_resource_id                 = data.azurerm_virtual_network.hub.id
      hub_peering_use_remote_gateways         = true
      hub_peering_allow_forwarded_traffic     = true
      
      resource_group_lock_enabled = true
      resource_group_lock_name    = "CanNotDelete"
    }
  }

  # Budget
  budget_enabled = true
  budgets = {
    monthly = {
      amount     = var.monthly_budget
      time_grain = "Monthly"
      time_period = {
        start_date = "2024-01-01T00:00:00Z"
        end_date   = "2027-12-31T23:59:59Z"
      }
      notifications = {
        forecast90 = {
          enabled        = true
          operator       = "GreaterThan"
          threshold      = 90
          threshold_type = "Forecasted"
          contact_emails = [var.owner_email, var.finance_email]
        }
        actual100 = {
          enabled        = true
          operator       = "GreaterThan"
          threshold      = 100
          threshold_type = "Actual"
          contact_emails = [var.owner_email, var.finance_email]
          contact_roles  = ["Owner"]
        }
      }
    }
  }
}
```

### Bicep Subscription Vending Example

```bicep
// main.bicep
targetScope = 'managementGroup'

@description('Workload name')
param workloadName string

@description('Environment')
@allowed(['dev', 'test', 'prod'])
param environment string

@description('Billing scope for subscription creation')
param billingScope string

@description('Address space for spoke VNet')
param addressSpace string

@description('Hub VNet resource ID')
param hubVnetId string

@description('Owner group object ID')
param ownerGroupId string

module subscriptionVending 'br/public:avm/ptn/lz/sub-vending:0.3.0' = {
  name: 'sub-vending-${workloadName}-${environment}'
  params: {
    subscriptionAliasEnabled: true
    subscriptionBillingScope: billingScope
    subscriptionAliasName: 'sub-${workloadName}-${environment}'
    subscriptionDisplayName: 'sub-${workloadName}-${environment}'
    subscriptionWorkload: environment == 'prod' ? 'Production' : 'DevTest'
    
    subscriptionManagementGroupAssociationEnabled: true
    subscriptionManagementGroupId: environment == 'prod' 
      ? '/providers/Microsoft.Management/managementGroups/mg-corp'
      : '/providers/Microsoft.Management/managementGroups/mg-sandbox'
    
    subscriptionTags: {
      workload: workloadName
      environment: environment
      createdBy: 'subscription-vending'
    }
    
    roleAssignments: [
      {
        principalId: ownerGroupId
        definition: '/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635' // Owner
        relativeScope: ''
        principalType: 'Group'
      }
    ]
    
    virtualNetworkEnabled: true
    virtualNetworkResourceGroupName: 'rg-networking-${workloadName}'
    virtualNetworkName: 'vnet-${workloadName}-${environment}'
    virtualNetworkAddressSpace: [addressSpace]
    virtualNetworkLocation: 'eastus'
    
    hubNetworkResourceId: hubVnetId
    virtualNetworkPeeringEnabled: true
    virtualNetworkUseRemoteGateway: true
  }
}

output subscriptionId string = subscriptionVending.outputs.subscriptionId
output virtualNetworkId string = subscriptionVending.outputs.virtualNetworkResourceId
```

---

## Monitoring and Logging

### Centralized Logging Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Centralized Logging Architecture                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  DATA SOURCES                                                       │
│  ├─ Azure Activity Logs (all subscriptions)                         │
│  ├─ Resource Diagnostic Logs                                        │
│  ├─ Microsoft Entra ID Sign-in/Audit Logs                          │
│  ├─ Azure Firewall Logs                                             │
│  ├─ NSG Flow Logs                                                   │
│  ├─ VM/Container Logs (Azure Monitor Agent)                         │
│  └─ Defender for Cloud Alerts                                       │
│                                                                      │
│                          │                                          │
│                          ▼                                          │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │            LOG ANALYTICS WORKSPACE (Management Sub)          │   │
│  │                                                              │   │
│  │  ├─ Tables: SecurityEvent, AzureActivity, SigninLogs, etc.  │   │
│  │  ├─ Retention: 90 days hot, 7 years archive                 │   │
│  │  ├─ Data Export to Storage (compliance)                     │   │
│  │  └─ Private Link for secure ingestion                       │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                          │                                          │
│                          ▼                                          │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    MICROSOFT SENTINEL                        │   │
│  │                                                              │   │
│  │  ├─ Data Connectors (Azure, M365, third-party)              │   │
│  │  ├─ Analytics Rules (scheduled, NRT, fusion)                │   │
│  │  ├─ Workbooks (security dashboards)                         │   │
│  │  ├─ Hunting Queries                                          │   │
│  │  ├─ Playbooks (automated response)                          │   │
│  │  └─ SOAR integration                                         │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Diagnostic Settings Policy

```json
// Policy: Deploy diagnostic settings for all supported resources
{
  "mode": "All",
  "policyRule": {
    "if": {
      "field": "type",
      "equals": "Microsoft.KeyVault/vaults"
    },
    "then": {
      "effect": "deployIfNotExists",
      "details": {
        "type": "Microsoft.Insights/diagnosticSettings",
        "name": "setByPolicy",
        "existenceCondition": {
          "allOf": [
            {
              "field": "Microsoft.Insights/diagnosticSettings/logs.enabled",
              "equals": "true"
            },
            {
              "field": "Microsoft.Insights/diagnosticSettings/workspaceId",
              "equals": "[parameters('logAnalyticsWorkspaceId')]"
            }
          ]
        },
        "roleDefinitionIds": [
          "/providers/microsoft.authorization/roleDefinitions/749f88d5-cbae-40b8-bcfc-e573ddc772fa",
          "/providers/microsoft.authorization/roleDefinitions/92aaf0da-9dab-42b6-94a3-d43ce8d16293"
        ],
        "deployment": {
          "properties": {
            "mode": "incremental",
            "template": {
              "$schema": "http://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#",
              "contentVersion": "1.0.0.0",
              "parameters": {
                "resourceName": { "type": "string" },
                "logAnalyticsWorkspaceId": { "type": "string" }
              },
              "resources": [
                {
                  "type": "Microsoft.KeyVault/vaults/providers/diagnosticSettings",
                  "apiVersion": "2021-05-01-preview",
                  "name": "[concat(parameters('resourceName'), '/Microsoft.Insights/setByPolicy')]",
                  "properties": {
                    "workspaceId": "[parameters('logAnalyticsWorkspaceId')]",
                    "logs": [
                      {
                        "categoryGroup": "allLogs",
                        "enabled": true
                      }
                    ],
                    "metrics": [
                      {
                        "category": "AllMetrics",
                        "enabled": true
                      }
                    ]
                  }
                }
              ]
            },
            "parameters": {
              "resourceName": { "value": "[field('name')]" },
              "logAnalyticsWorkspaceId": { "value": "[parameters('logAnalyticsWorkspaceId')]" }
            }
          }
        }
      }
    }
  },
  "parameters": {
    "logAnalyticsWorkspaceId": {
      "type": "String",
      "metadata": {
        "displayName": "Log Analytics Workspace ID",
        "description": "Central Log Analytics workspace for diagnostic logs"
      }
    }
  }
}
```

---

## Security Checklists

### Pre-Deployment Checklist

| Category | Check | Status |
|----------|-------|--------|
| **Tenant Setup** | | |
| | Microsoft Entra ID tenant configured | ☐ |
| | Break-glass accounts created and secured | ☐ |
| | Conditional Access baseline policies | ☐ |
| | PIM configured for privileged roles | ☐ |
| **Management Groups** | | |
| | Hierarchy designed and documented | ☐ |
| | Root management group secured | ☐ |
| | Policy inheritance validated | ☐ |
| **Platform Subscriptions** | | |
| | Identity subscription created | ☐ |
| | Management subscription created | ☐ |
| | Connectivity subscription created | ☐ |
| **Network Foundation** | | |
| | Hub VNet deployed | ☐ |
| | Azure Firewall configured | ☐ |
| | Private DNS zones created | ☐ |
| | ExpressRoute/VPN configured | ☐ |
| **Security Baseline** | | |
| | Defender for Cloud enabled | ☐ |
| | Microsoft Sentinel deployed | ☐ |
| | Diagnostic settings policy assigned | ☐ |
| | Security contacts configured | ☐ |

### Application Landing Zone Checklist

| Category | Check | Status |
|----------|-------|--------|
| **Subscription** | | |
| | Created via subscription vending | ☐ |
| | Placed in correct management group | ☐ |
| | Required tags applied | ☐ |
| | Budget configured | ☐ |
| **RBAC** | | |
| | Owner role assigned to workload team | ☐ |
| | Reader role for security team | ☐ |
| | No standing privileged access | ☐ |
| **Network** | | |
| | Spoke VNet created | ☐ |
| | Peered to hub with correct settings | ☐ |
| | NSGs applied to all subnets | ☐ |
| | UDRs routing through firewall | ☐ |
| **Security** | | |
| | Private endpoints for PaaS | ☐ |
| | No public IPs (Corp) | ☐ |
| | Diagnostic logs flowing | ☐ |
| | Defender plans active | ☐ |

### Ongoing Security Review

| Review Item | Frequency | Owner |
|-------------|-----------|-------|
| PIM access reviews | Quarterly | Security Team |
| Policy compliance | Weekly | Platform Team |
| Defender recommendations | Weekly | Security Team |
| Network flow analysis | Monthly | Network Team |
| Cost anomaly review | Weekly | FinOps Team |
| Sentinel incident review | Daily | SOC |
| Subscription inventory | Monthly | Platform Team |

---

## Resources

### Microsoft Documentation
- [Azure Landing Zones](https://learn.microsoft.com/azure/cloud-adoption-framework/ready/landing-zone/)
- [Azure Landing Zone Policies](https://github.com/Azure/Enterprise-Scale/wiki/ALZ-Policies)
- [Security Design Area](https://learn.microsoft.com/azure/cloud-adoption-framework/ready/landing-zone/design-area/security)
- [Zero Trust in Landing Zones](https://learn.microsoft.com/azure/cloud-adoption-framework/ready/landing-zone/design-area/security-zero-trust)

### GitHub Repositories
- [Azure Landing Zones (Enterprise-Scale)](https://github.com/Azure/Enterprise-Scale)
- [ALZ Bicep](https://github.com/Azure/ALZ-Bicep)
- [ALZ Terraform](https://github.com/Azure/terraform-azurerm-caf-enterprise-scale)
- [Subscription Vending - Bicep](https://github.com/Azure/bicep-lz-vending)
- [Subscription Vending - Terraform](https://github.com/Azure/terraform-azurerm-lz-vending)

### Tools
- [AzAdvertizer](https://www.azadvertizer.net/) - Azure Policy and RBAC reference
- [Azure Governance Visualizer](https://github.com/JulianHayward/Azure-MG-Sub-Governance-Reporting)
- [PSRule for Azure](https://azure.github.io/PSRule.Rules.Azure/) - Azure best practices validation
