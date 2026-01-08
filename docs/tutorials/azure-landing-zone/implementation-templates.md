# Azure Landing Zone - Implementation Templates

Practical Infrastructure-as-Code templates and configurations for implementing secure Azure Landing Zones.

## Table of Contents

1. [Management Group Hierarchy](#management-group-hierarchy)
2. [Policy Definitions](#policy-definitions)
3. [RBAC Role Definitions](#rbac-role-definitions)
4. [Network Templates](#network-templates)
5. [Defender for Cloud Configuration](#defender-for-cloud-configuration)
6. [Sentinel Analytics Rules](#sentinel-analytics-rules)
7. [Compliance Queries](#compliance-queries)

---

## Management Group Hierarchy

### Bicep Template

```bicep
// management-groups.bicep
targetScope = 'tenant'

@description('Organization prefix')
param orgPrefix string = 'contoso'

// Intermediate Root
resource intermediateRoot 'Microsoft.Management/managementGroups@2023-04-01' = {
  name: orgPrefix
  properties: {
    displayName: orgPrefix
  }
}

// Platform Management Group
resource platform 'Microsoft.Management/managementGroups@2023-04-01' = {
  name: '${orgPrefix}-platform'
  properties: {
    displayName: 'Platform'
    details: {
      parent: {
        id: intermediateRoot.id
      }
    }
  }
}

// Platform Children
resource identity 'Microsoft.Management/managementGroups@2023-04-01' = {
  name: '${orgPrefix}-identity'
  properties: {
    displayName: 'Identity'
    details: {
      parent: {
        id: platform.id
      }
    }
  }
}

resource management 'Microsoft.Management/managementGroups@2023-04-01' = {
  name: '${orgPrefix}-management'
  properties: {
    displayName: 'Management'
    details: {
      parent: {
        id: platform.id
      }
    }
  }
}

resource connectivity 'Microsoft.Management/managementGroups@2023-04-01' = {
  name: '${orgPrefix}-connectivity'
  properties: {
    displayName: 'Connectivity'
    details: {
      parent: {
        id: platform.id
      }
    }
  }
}

// Landing Zones Management Group
resource landingZones 'Microsoft.Management/managementGroups@2023-04-01' = {
  name: '${orgPrefix}-landingzones'
  properties: {
    displayName: 'Landing Zones'
    details: {
      parent: {
        id: intermediateRoot.id
      }
    }
  }
}

// Landing Zone Children
resource corp 'Microsoft.Management/managementGroups@2023-04-01' = {
  name: '${orgPrefix}-corp'
  properties: {
    displayName: 'Corp'
    details: {
      parent: {
        id: landingZones.id
      }
    }
  }
}

resource online 'Microsoft.Management/managementGroups@2023-04-01' = {
  name: '${orgPrefix}-online'
  properties: {
    displayName: 'Online'
    details: {
      parent: {
        id: landingZones.id
      }
    }
  }
}

resource confidential 'Microsoft.Management/managementGroups@2023-04-01' = {
  name: '${orgPrefix}-confidential'
  properties: {
    displayName: 'Confidential'
    details: {
      parent: {
        id: landingZones.id
      }
    }
  }
}

// Sandbox
resource sandbox 'Microsoft.Management/managementGroups@2023-04-01' = {
  name: '${orgPrefix}-sandbox'
  properties: {
    displayName: 'Sandbox'
    details: {
      parent: {
        id: intermediateRoot.id
      }
    }
  }
}

// Decommissioned
resource decommissioned 'Microsoft.Management/managementGroups@2023-04-01' = {
  name: '${orgPrefix}-decommissioned'
  properties: {
    displayName: 'Decommissioned'
    details: {
      parent: {
        id: intermediateRoot.id
      }
    }
  }
}

output intermediateRootId string = intermediateRoot.id
output platformId string = platform.id
output landingZonesId string = landingZones.id
```

### Terraform Configuration

```hcl
# management-groups.tf

locals {
  org_prefix = "contoso"
}

# Intermediate Root
resource "azurerm_management_group" "intermediate_root" {
  display_name = local.org_prefix
  name         = local.org_prefix
}

# Platform
resource "azurerm_management_group" "platform" {
  display_name               = "Platform"
  name                       = "${local.org_prefix}-platform"
  parent_management_group_id = azurerm_management_group.intermediate_root.id
}

resource "azurerm_management_group" "identity" {
  display_name               = "Identity"
  name                       = "${local.org_prefix}-identity"
  parent_management_group_id = azurerm_management_group.platform.id
}

resource "azurerm_management_group" "management" {
  display_name               = "Management"
  name                       = "${local.org_prefix}-management"
  parent_management_group_id = azurerm_management_group.platform.id
}

resource "azurerm_management_group" "connectivity" {
  display_name               = "Connectivity"
  name                       = "${local.org_prefix}-connectivity"
  parent_management_group_id = azurerm_management_group.platform.id
}

# Landing Zones
resource "azurerm_management_group" "landing_zones" {
  display_name               = "Landing Zones"
  name                       = "${local.org_prefix}-landingzones"
  parent_management_group_id = azurerm_management_group.intermediate_root.id
}

resource "azurerm_management_group" "corp" {
  display_name               = "Corp"
  name                       = "${local.org_prefix}-corp"
  parent_management_group_id = azurerm_management_group.landing_zones.id
}

resource "azurerm_management_group" "online" {
  display_name               = "Online"
  name                       = "${local.org_prefix}-online"
  parent_management_group_id = azurerm_management_group.landing_zones.id
}

# Sandbox & Decommissioned
resource "azurerm_management_group" "sandbox" {
  display_name               = "Sandbox"
  name                       = "${local.org_prefix}-sandbox"
  parent_management_group_id = azurerm_management_group.intermediate_root.id
}

resource "azurerm_management_group" "decommissioned" {
  display_name               = "Decommissioned"
  name                       = "${local.org_prefix}-decommissioned"
  parent_management_group_id = azurerm_management_group.intermediate_root.id
}
```

---

## Policy Definitions

### Security Baseline Initiative

```json
{
  "name": "alz-security-baseline",
  "properties": {
    "displayName": "ALZ Security Baseline",
    "description": "Security baseline policies for Azure Landing Zones",
    "policyType": "Custom",
    "metadata": {
      "category": "Security",
      "version": "1.0.0"
    },
    "policyDefinitions": [
      {
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/0015ea4d-51ff-4ce3-8d8c-f3f8f0179a56",
        "policyDefinitionReferenceId": "AuditVMsWithoutDR"
      },
      {
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/06a78e20-9358-41c9-923c-fb736d382a4d",
        "policyDefinitionReferenceId": "AuditSQLServerAuditing"
      },
      {
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/0961003e-5a0a-4549-abde-af6a37f2724d",
        "policyDefinitionReferenceId": "DenyPublicIPVMs"
      },
      {
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/1a5b4dca-0b6f-4cf5-907c-56316bc1bf3d",
        "policyDefinitionReferenceId": "AuditKeyVaultRecoverable"
      },
      {
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/22bee202-a82f-4305-9a2a-6d7f44d4dedb",
        "policyDefinitionReferenceId": "DenyAppGatewayWithoutWAF"
      },
      {
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/34c877ad-507e-4c82-993e-3452a6e0ad3c",
        "policyDefinitionReferenceId": "AuditStorageSecureTransfer"
      },
      {
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/404c3081-a854-4457-ae30-26a93ef643f9",
        "policyDefinitionReferenceId": "AuditStorageHttps"
      },
      {
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/4f11b553-d42e-4e3a-89be-32ca364cad4c",
        "policyDefinitionReferenceId": "DeployLogAnalyticsAgentWindows"
      }
    ]
  }
}
```

### Custom Policy: Deny Resources Without Required Tags

```json
{
  "mode": "Indexed",
  "policyRule": {
    "if": {
      "anyOf": [
        {
          "field": "[concat('tags[', parameters('tagName1'), ']')]",
          "exists": "false"
        },
        {
          "field": "[concat('tags[', parameters('tagName2'), ']')]",
          "exists": "false"
        },
        {
          "field": "[concat('tags[', parameters('tagName3'), ']')]",
          "exists": "false"
        }
      ]
    },
    "then": {
      "effect": "deny"
    }
  },
  "parameters": {
    "tagName1": {
      "type": "String",
      "metadata": {
        "displayName": "Required Tag 1",
        "description": "Name of the first required tag"
      },
      "defaultValue": "costCenter"
    },
    "tagName2": {
      "type": "String",
      "metadata": {
        "displayName": "Required Tag 2",
        "description": "Name of the second required tag"
      },
      "defaultValue": "owner"
    },
    "tagName3": {
      "type": "String",
      "metadata": {
        "displayName": "Required Tag 3",
        "description": "Name of the third required tag"
      },
      "defaultValue": "environment"
    }
  }
}
```

### Custom Policy: Enforce Private Endpoints for Storage

```json
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
          "field": "Microsoft.Storage/storageAccounts/publicNetworkAccess",
          "notEquals": "Disabled"
        }
      ]
    },
    "then": {
      "effect": "[parameters('effect')]"
    }
  },
  "parameters": {
    "effect": {
      "type": "String",
      "metadata": {
        "displayName": "Effect",
        "description": "Enable or disable the execution of the policy"
      },
      "allowedValues": ["Audit", "Deny", "Disabled"],
      "defaultValue": "Deny"
    }
  }
}
```

### Custom Policy: Deploy NSG Flow Logs

```json
{
  "mode": "Indexed",
  "policyRule": {
    "if": {
      "field": "type",
      "equals": "Microsoft.Network/networkSecurityGroups"
    },
    "then": {
      "effect": "deployIfNotExists",
      "details": {
        "type": "Microsoft.Network/networkWatchers/flowLogs",
        "resourceGroupName": "[parameters('networkWatcherRG')]",
        "name": "[concat('networkWatcher_', field('location'), '/flowlog-', field('name'))]",
        "existenceCondition": {
          "field": "Microsoft.Network/networkWatchers/flowLogs/targetResourceId",
          "equals": "[field('id')]"
        },
        "roleDefinitionIds": [
          "/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"
        ],
        "deployment": {
          "properties": {
            "mode": "incremental",
            "template": {
              "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
              "contentVersion": "1.0.0.0",
              "parameters": {
                "nsgName": { "type": "string" },
                "nsgRG": { "type": "string" },
                "location": { "type": "string" },
                "storageId": { "type": "string" },
                "workspaceId": { "type": "string" },
                "workspaceRegion": { "type": "string" },
                "workspaceResourceId": { "type": "string" }
              },
              "resources": [
                {
                  "type": "Microsoft.Network/networkWatchers/flowLogs",
                  "apiVersion": "2023-05-01",
                  "name": "[concat('networkWatcher_', parameters('location'), '/flowlog-', parameters('nsgName'))]",
                  "location": "[parameters('location')]",
                  "properties": {
                    "targetResourceId": "[resourceId(parameters('nsgRG'), 'Microsoft.Network/networkSecurityGroups', parameters('nsgName'))]",
                    "storageId": "[parameters('storageId')]",
                    "enabled": true,
                    "flowAnalyticsConfiguration": {
                      "networkWatcherFlowAnalyticsConfiguration": {
                        "enabled": true,
                        "workspaceId": "[parameters('workspaceId')]",
                        "workspaceRegion": "[parameters('workspaceRegion')]",
                        "workspaceResourceId": "[parameters('workspaceResourceId')]",
                        "trafficAnalyticsInterval": 10
                      }
                    },
                    "retentionPolicy": {
                      "days": 90,
                      "enabled": true
                    },
                    "format": {
                      "type": "JSON",
                      "version": 2
                    }
                  }
                }
              ]
            },
            "parameters": {
              "nsgName": { "value": "[field('name')]" },
              "nsgRG": { "value": "[resourceGroup().name]" },
              "location": { "value": "[field('location')]" },
              "storageId": { "value": "[parameters('storageAccountId')]" },
              "workspaceId": { "value": "[parameters('workspaceId')]" },
              "workspaceRegion": { "value": "[parameters('workspaceRegion')]" },
              "workspaceResourceId": { "value": "[parameters('workspaceResourceId')]" }
            }
          }
        }
      }
    }
  },
  "parameters": {
    "networkWatcherRG": {
      "type": "String",
      "defaultValue": "NetworkWatcherRG"
    },
    "storageAccountId": {
      "type": "String"
    },
    "workspaceId": {
      "type": "String"
    },
    "workspaceRegion": {
      "type": "String"
    },
    "workspaceResourceId": {
      "type": "String"
    }
  }
}
```

---

## RBAC Role Definitions

### Network Operations Role

```json
{
  "Name": "Network Operations",
  "Id": "00000000-0000-0000-0000-000000000001",
  "IsCustom": true,
  "Description": "Can manage network resources but not create/delete VNets or modify peerings",
  "Actions": [
    "Microsoft.Network/networkSecurityGroups/*",
    "Microsoft.Network/routeTables/*",
    "Microsoft.Network/applicationGateways/*",
    "Microsoft.Network/loadBalancers/*",
    "Microsoft.Network/privateEndpoints/*",
    "Microsoft.Network/privateDnsZones/*",
    "Microsoft.Network/publicIPAddresses/read",
    "Microsoft.Network/virtualNetworks/read",
    "Microsoft.Network/virtualNetworks/subnets/read",
    "Microsoft.Network/virtualNetworks/subnets/join/action",
    "Microsoft.Resources/subscriptions/resourceGroups/read",
    "Microsoft.Support/*"
  ],
  "NotActions": [],
  "DataActions": [],
  "NotDataActions": [],
  "AssignableScopes": [
    "/providers/Microsoft.Management/managementGroups/contoso-landingzones"
  ]
}
```

### Security Reader Plus Role

```json
{
  "Name": "Security Reader Plus",
  "Id": "00000000-0000-0000-0000-000000000002",
  "IsCustom": true,
  "Description": "Security Reader with additional diagnostic access",
  "Actions": [
    "*/read",
    "Microsoft.Authorization/*/read",
    "Microsoft.Insights/alertRules/*",
    "Microsoft.Insights/diagnosticSettings/*",
    "Microsoft.OperationalInsights/workspaces/*/read",
    "Microsoft.OperationalInsights/workspaces/query/read",
    "Microsoft.Security/*",
    "Microsoft.Support/*"
  ],
  "NotActions": [],
  "DataActions": [
    "Microsoft.KeyVault/vaults/secrets/getSecret/action"
  ],
  "NotDataActions": [],
  "AssignableScopes": [
    "/providers/Microsoft.Management/managementGroups/contoso"
  ]
}
```

### Application Owner Role

```json
{
  "Name": "Application Owner",
  "Id": "00000000-0000-0000-0000-000000000003",
  "IsCustom": true,
  "Description": "Full access to manage application resources without RBAC or network changes",
  "Actions": [
    "*"
  ],
  "NotActions": [
    "Microsoft.Authorization/*/Delete",
    "Microsoft.Authorization/*/Write",
    "Microsoft.Authorization/elevateAccess/Action",
    "Microsoft.Blueprint/blueprintAssignments/write",
    "Microsoft.Blueprint/blueprintAssignments/delete",
    "Microsoft.Network/virtualNetworks/delete",
    "Microsoft.Network/virtualNetworks/write",
    "Microsoft.Network/virtualNetworks/peer/action",
    "Microsoft.Network/virtualNetworks/virtualNetworkPeerings/*"
  ],
  "DataActions": [],
  "NotDataActions": [],
  "AssignableScopes": [
    "/providers/Microsoft.Management/managementGroups/contoso-landingzones"
  ]
}
```

---

## Network Templates

### Hub VNet with Azure Firewall

```bicep
// hub-network.bicep
param location string = resourceGroup().location
param hubVnetName string = 'vnet-hub-${location}'
param hubVnetAddressPrefix string = '10.0.0.0/16'

// Subnets
var gatewaySubnetPrefix = '10.0.0.0/27'
var azureFirewallSubnetPrefix = '10.0.1.0/26'
var azureBastionSubnetPrefix = '10.0.2.0/26'
var dnsSubnetPrefix = '10.0.3.0/28'
var sharedServicesSubnetPrefix = '10.0.4.0/24'

// Hub VNet
resource hubVnet 'Microsoft.Network/virtualNetworks@2023-05-01' = {
  name: hubVnetName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [hubVnetAddressPrefix]
    }
    subnets: [
      {
        name: 'GatewaySubnet'
        properties: {
          addressPrefix: gatewaySubnetPrefix
        }
      }
      {
        name: 'AzureFirewallSubnet'
        properties: {
          addressPrefix: azureFirewallSubnetPrefix
        }
      }
      {
        name: 'AzureBastionSubnet'
        properties: {
          addressPrefix: azureBastionSubnetPrefix
        }
      }
      {
        name: 'snet-dns'
        properties: {
          addressPrefix: dnsSubnetPrefix
          delegations: [
            {
              name: 'Microsoft.Network.dnsResolvers'
              properties: {
                serviceName: 'Microsoft.Network/dnsResolvers'
              }
            }
          ]
        }
      }
      {
        name: 'snet-shared-services'
        properties: {
          addressPrefix: sharedServicesSubnetPrefix
          networkSecurityGroup: {
            id: sharedServicesNsg.id
          }
        }
      }
    ]
  }
}

// NSG for Shared Services
resource sharedServicesNsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'nsg-shared-services'
  location: location
  properties: {
    securityRules: [
      {
        name: 'AllowBastionInbound'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: azureBastionSubnetPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRanges: ['22', '3389']
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

// Azure Firewall
resource firewallPip 'Microsoft.Network/publicIPAddresses@2023-05-01' = {
  name: 'pip-azfw-${location}'
  location: location
  sku: {
    name: 'Standard'
    tier: 'Regional'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

resource firewallPolicy 'Microsoft.Network/firewallPolicies@2023-05-01' = {
  name: 'afwp-hub-${location}'
  location: location
  properties: {
    sku: {
      tier: 'Premium'
    }
    threatIntelMode: 'Deny'
    dnsSettings: {
      enableProxy: true
    }
    intrusionDetection: {
      mode: 'Deny'
    }
  }
}

resource azureFirewall 'Microsoft.Network/azureFirewalls@2023-05-01' = {
  name: 'afw-hub-${location}'
  location: location
  properties: {
    sku: {
      name: 'AZFW_VNet'
      tier: 'Premium'
    }
    firewallPolicy: {
      id: firewallPolicy.id
    }
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: {
            id: '${hubVnet.id}/subnets/AzureFirewallSubnet'
          }
          publicIPAddress: {
            id: firewallPip.id
          }
        }
      }
    ]
  }
}

// Azure Bastion
resource bastionPip 'Microsoft.Network/publicIPAddresses@2023-05-01' = {
  name: 'pip-bastion-${location}'
  location: location
  sku: {
    name: 'Standard'
    tier: 'Regional'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

resource bastion 'Microsoft.Network/bastionHosts@2023-05-01' = {
  name: 'bas-hub-${location}'
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    enableTunneling: true
    enableFileCopy: true
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: {
            id: '${hubVnet.id}/subnets/AzureBastionSubnet'
          }
          publicIPAddress: {
            id: bastionPip.id
          }
        }
      }
    ]
  }
}

output hubVnetId string = hubVnet.id
output firewallPrivateIp string = azureFirewall.properties.ipConfigurations[0].properties.privateIPAddress
```

### Spoke VNet with Peering

```bicep
// spoke-network.bicep
param location string = resourceGroup().location
param spokeName string
param spokeAddressPrefix string
param hubVnetId string
param firewallPrivateIp string

var vnetName = 'vnet-${spokeName}-${location}'

// Route Table (force traffic through firewall)
resource routeTable 'Microsoft.Network/routeTables@2023-05-01' = {
  name: 'rt-${spokeName}'
  location: location
  properties: {
    disableBgpRoutePropagation: true
    routes: [
      {
        name: 'default-to-firewall'
        properties: {
          addressPrefix: '0.0.0.0/0'
          nextHopType: 'VirtualAppliance'
          nextHopIpAddress: firewallPrivateIp
        }
      }
    ]
  }
}

// NSG for workload subnets
resource workloadNsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'nsg-${spokeName}-workload'
  location: location
  properties: {
    securityRules: [
      {
        name: 'AllowHttpsInbound'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: 'VirtualNetwork'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '443'
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

// Spoke VNet
resource spokeVnet 'Microsoft.Network/virtualNetworks@2023-05-01' = {
  name: vnetName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [spokeAddressPrefix]
    }
    subnets: [
      {
        name: 'snet-workload'
        properties: {
          addressPrefix: cidrSubnet(spokeAddressPrefix, 24, 0)
          networkSecurityGroup: {
            id: workloadNsg.id
          }
          routeTable: {
            id: routeTable.id
          }
          privateEndpointNetworkPolicies: 'Disabled'
        }
      }
      {
        name: 'snet-private-endpoints'
        properties: {
          addressPrefix: cidrSubnet(spokeAddressPrefix, 24, 1)
          privateEndpointNetworkPolicies: 'Disabled'
        }
      }
    ]
  }
}

// Peering: Spoke to Hub
resource spokeToHubPeering 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2023-05-01' = {
  parent: spokeVnet
  name: 'peer-to-hub'
  properties: {
    remoteVirtualNetwork: {
      id: hubVnetId
    }
    allowVirtualNetworkAccess: true
    allowForwardedTraffic: true
    allowGatewayTransit: false
    useRemoteGateways: true
  }
}

output spokeVnetId string = spokeVnet.id
output workloadSubnetId string = '${spokeVnet.id}/subnets/snet-workload'
output privateEndpointSubnetId string = '${spokeVnet.id}/subnets/snet-private-endpoints'
```

---

## Defender for Cloud Configuration

### Enable All Defender Plans

```bicep
// defender-for-cloud.bicep
targetScope = 'subscription'

param securityContactEmail string
param logAnalyticsWorkspaceId string

// Defender for Servers Plan 2
resource defenderServers 'Microsoft.Security/pricings@2023-01-01' = {
  name: 'VirtualMachines'
  properties: {
    pricingTier: 'Standard'
    subPlan: 'P2'
    extensions: [
      { name: 'MdeDesignatedSubscription', isEnabled: 'True' }
      { name: 'AgentlessVmScanning', isEnabled: 'True' }
    ]
  }
}

// Defender for SQL
resource defenderSql 'Microsoft.Security/pricings@2023-01-01' = {
  name: 'SqlServers'
  properties: {
    pricingTier: 'Standard'
  }
}

resource defenderSqlVms 'Microsoft.Security/pricings@2023-01-01' = {
  name: 'SqlServerVirtualMachines'
  properties: {
    pricingTier: 'Standard'
  }
}

// Defender for Storage
resource defenderStorage 'Microsoft.Security/pricings@2023-01-01' = {
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
      { name: 'SensitiveDataDiscovery', isEnabled: 'True' }
    ]
  }
}

// Defender for Containers
resource defenderContainers 'Microsoft.Security/pricings@2023-01-01' = {
  name: 'Containers'
  properties: {
    pricingTier: 'Standard'
    extensions: [
      { name: 'ContainerRegistriesVulnerabilityAssessments', isEnabled: 'True' }
    ]
  }
}

// Defender for Key Vault
resource defenderKeyVault 'Microsoft.Security/pricings@2023-01-01' = {
  name: 'KeyVaults'
  properties: {
    pricingTier: 'Standard'
  }
}

// Defender for App Service
resource defenderAppService 'Microsoft.Security/pricings@2023-01-01' = {
  name: 'AppServices'
  properties: {
    pricingTier: 'Standard'
  }
}

// Defender for DNS
resource defenderDns 'Microsoft.Security/pricings@2023-01-01' = {
  name: 'Dns'
  properties: {
    pricingTier: 'Standard'
  }
}

// Defender CSPM
resource defenderCspm 'Microsoft.Security/pricings@2023-01-01' = {
  name: 'CloudPosture'
  properties: {
    pricingTier: 'Standard'
    extensions: [
      { name: 'SensitiveDataDiscovery', isEnabled: 'True' }
      { name: 'ContainerRegistriesVulnerabilityAssessments', isEnabled: 'True' }
      { name: 'AgentlessDiscoveryForKubernetes', isEnabled: 'True' }
      { name: 'AgentlessVmScanning', isEnabled: 'True' }
    ]
  }
}

// Security Contact
resource securityContact 'Microsoft.Security/securityContacts@2020-01-01-preview' = {
  name: 'default'
  properties: {
    emails: securityContactEmail
    alertNotifications: {
      state: 'On'
      minimalSeverity: 'Medium'
    }
    notificationsByRole: {
      state: 'On'
      roles: ['Owner', 'Contributor', 'ServiceAdmin']
    }
  }
}

// Auto-provisioning settings
resource autoProvisioningLA 'Microsoft.Security/autoProvisioningSettings@2017-08-01-preview' = {
  name: 'default'
  properties: {
    autoProvision: 'On'
  }
}

// Continuous Export to Log Analytics
resource continuousExport 'Microsoft.Security/automations@2019-01-01-preview' = {
  name: 'ExportToWorkspace'
  location: 'global'
  properties: {
    isEnabled: true
    scopes: [
      {
        scopePath: subscription().id
      }
    ]
    sources: [
      {
        eventSource: 'Alerts'
        ruleSets: [
          {
            rules: [
              {
                propertyJPath: 'Severity'
                propertyType: 'String'
                expectedValue: 'High'
                operator: 'Equals'
              }
            ]
          }
        ]
      }
      {
        eventSource: 'SecureScores'
      }
      {
        eventSource: 'SecureScoreControls'
      }
      {
        eventSource: 'Recommendations'
      }
    ]
    actions: [
      {
        actionType: 'Workspace'
        workspaceResourceId: logAnalyticsWorkspaceId
      }
    ]
  }
}
```

---

## Sentinel Analytics Rules

### Suspicious Azure AD Sign-in

```json
{
  "kind": "Scheduled",
  "properties": {
    "displayName": "Suspicious Azure AD Sign-in Activity",
    "description": "Detects unusual sign-in patterns that may indicate account compromise",
    "severity": "Medium",
    "enabled": true,
    "query": "SigninLogs\n| where TimeGenerated > ago(1h)\n| where ResultType == 0 // Successful sign-ins\n| where RiskLevelAggregated in (\"medium\", \"high\") or RiskState == \"atRisk\"\n| extend LocationDetails = parse_json(LocationDetails)\n| extend City = tostring(LocationDetails.city)\n| extend Country = tostring(LocationDetails.countryOrRegion)\n| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, City, Country, RiskLevelAggregated, RiskState, UserAgent\n| order by TimeGenerated desc",
    "queryFrequency": "PT1H",
    "queryPeriod": "PT1H",
    "triggerOperator": "GreaterThan",
    "triggerThreshold": 0,
    "suppressionDuration": "PT5H",
    "suppressionEnabled": false,
    "tactics": ["InitialAccess", "CredentialAccess"],
    "techniques": ["T1078", "T1110"],
    "entityMappings": [
      {
        "entityType": "Account",
        "fieldMappings": [
          { "identifier": "FullName", "columnName": "UserPrincipalName" }
        ]
      },
      {
        "entityType": "IP",
        "fieldMappings": [
          { "identifier": "Address", "columnName": "IPAddress" }
        ]
      }
    ],
    "incidentConfiguration": {
      "createIncident": true,
      "groupingConfiguration": {
        "enabled": true,
        "reopenClosedIncident": false,
        "lookbackDuration": "PT5H",
        "matchingMethod": "AllEntities"
      }
    }
  }
}
```

### Azure Resource Deletion Spike

```json
{
  "kind": "Scheduled",
  "properties": {
    "displayName": "Unusual Azure Resource Deletion Activity",
    "description": "Detects unusual spike in resource deletions that may indicate destructive activity",
    "severity": "High",
    "enabled": true,
    "query": "AzureActivity\n| where TimeGenerated > ago(1h)\n| where OperationNameValue endswith \"delete\"\n| where ActivityStatusValue == \"Success\"\n| summarize DeleteCount = count() by Caller, CallerIpAddress, bin(TimeGenerated, 5m)\n| where DeleteCount > 10\n| project TimeGenerated, Caller, CallerIpAddress, DeleteCount\n| order by DeleteCount desc",
    "queryFrequency": "PT1H",
    "queryPeriod": "PT1H",
    "triggerOperator": "GreaterThan",
    "triggerThreshold": 0,
    "suppressionDuration": "PT5H",
    "suppressionEnabled": false,
    "tactics": ["Impact"],
    "techniques": ["T1485"],
    "entityMappings": [
      {
        "entityType": "Account",
        "fieldMappings": [
          { "identifier": "FullName", "columnName": "Caller" }
        ]
      },
      {
        "entityType": "IP",
        "fieldMappings": [
          { "identifier": "Address", "columnName": "CallerIpAddress" }
        ]
      }
    ]
  }
}
```

### Key Vault Secret Access from Unusual IP

```json
{
  "kind": "Scheduled",
  "properties": {
    "displayName": "Key Vault Secret Access from New IP",
    "description": "Detects Key Vault secret access from IP addresses not seen in the past 14 days",
    "severity": "Medium",
    "enabled": true,
    "query": "let knownIPs = AzureDiagnostics\n| where TimeGenerated between (ago(14d) .. ago(1d))\n| where ResourceType == \"VAULTS\"\n| where OperationName == \"SecretGet\"\n| distinct CallerIPAddress;\nAzureDiagnostics\n| where TimeGenerated > ago(1h)\n| where ResourceType == \"VAULTS\"\n| where OperationName == \"SecretGet\"\n| where CallerIPAddress !in (knownIPs)\n| project TimeGenerated, Resource, OperationName, CallerIPAddress, identity_claim_upn_s, ResultType\n| order by TimeGenerated desc",
    "queryFrequency": "PT1H",
    "queryPeriod": "P14D",
    "triggerOperator": "GreaterThan",
    "triggerThreshold": 0,
    "tactics": ["CredentialAccess"],
    "techniques": ["T1555"],
    "entityMappings": [
      {
        "entityType": "Account",
        "fieldMappings": [
          { "identifier": "FullName", "columnName": "identity_claim_upn_s" }
        ]
      },
      {
        "entityType": "IP",
        "fieldMappings": [
          { "identifier": "Address", "columnName": "CallerIPAddress" }
        ]
      },
      {
        "entityType": "AzureResource",
        "fieldMappings": [
          { "identifier": "ResourceId", "columnName": "Resource" }
        ]
      }
    ]
  }
}
```

---

## Compliance Queries

### Azure Resource Graph - Non-Compliant Resources

```kusto
// Find resources not compliant with security policies
policyresources
| where type == 'microsoft.policyinsights/policystates'
| where properties.complianceState == 'NonCompliant'
| extend policyDefinitionId = tostring(properties.policyDefinitionId)
| extend policyAssignmentId = tostring(properties.policyAssignmentId)
| extend resourceId = tostring(properties.resourceId)
| extend resourceType = tostring(properties.resourceType)
| summarize NonCompliantCount = count() by policyDefinitionId, resourceType
| order by NonCompliantCount desc
| take 20
```

### Resources Without Required Tags

```kusto
// Find resources missing required tags
resources
| where isempty(tags.costCenter) or isempty(tags.owner) or isempty(tags.environment)
| project name, type, resourceGroup, subscriptionId,
    hasCostCenter = isnotempty(tags.costCenter),
    hasOwner = isnotempty(tags.owner),
    hasEnvironment = isnotempty(tags.environment)
| order by type asc
```

### Storage Accounts with Public Access

```kusto
// Find storage accounts with public blob access enabled
resources
| where type == 'microsoft.storage/storageaccounts'
| where properties.allowBlobPublicAccess == true
    or properties.publicNetworkAccess == 'Enabled'
| project name, resourceGroup, subscriptionId, location,
    allowBlobPublicAccess = properties.allowBlobPublicAccess,
    publicNetworkAccess = properties.publicNetworkAccess,
    minimumTlsVersion = properties.minimumTlsVersion
```

### VMs Without Defender for Cloud Agent

```kusto
// Find VMs without Microsoft Defender for Cloud agent
resources
| where type == 'microsoft.compute/virtualmachines'
| extend vmId = id
| join kind=leftouter (
    resources
    | where type == 'microsoft.compute/virtualmachines/extensions'
    | where name contains 'MDE' or name contains 'AzureSecurityCenter'
    | extend vmId = tostring(split(id, '/extensions/')[0])
) on vmId
| where isempty(vmId1)
| project name, resourceGroup, subscriptionId, location
```

### Network Security Groups with Risky Rules

```kusto
// Find NSGs with overly permissive rules
resources
| where type == 'microsoft.network/networksecuritygroups'
| mv-expand rules = properties.securityRules
| where rules.properties.direction == 'Inbound'
    and rules.properties.access == 'Allow'
    and (rules.properties.sourceAddressPrefix == '*'
        or rules.properties.sourceAddressPrefix == 'Internet'
        or rules.properties.sourceAddressPrefix == '0.0.0.0/0')
    and (rules.properties.destinationPortRange == '*'
        or rules.properties.destinationPortRange == '22'
        or rules.properties.destinationPortRange == '3389')
| project nsgName = name, ruleName = rules.name, 
    sourcePrefix = rules.properties.sourceAddressPrefix,
    destPort = rules.properties.destinationPortRange,
    resourceGroup, subscriptionId
```

---

## Quick Reference

### ALZ Policy Effects

| Effect | Use Case |
|--------|----------|
| **Deny** | Block non-compliant resources |
| **Audit** | Log non-compliance, don't block |
| **Modify** | Auto-fix configurations |
| **DeployIfNotExists** | Deploy required configurations |
| **AuditIfNotExists** | Audit missing related resources |
| **Append** | Add tags or properties |
| **Disabled** | Turn off policy |

### Key Management Groups

| Management Group | Purpose |
|-----------------|---------|
| Intermediate Root | Organization-wide policies |
| Platform | Shared services |
| Landing Zones | Application workloads |
| Corp | Private connectivity apps |
| Online | Internet-facing apps |
| Sandbox | Development/testing |
| Decommissioned | Retired subscriptions |

### Defender for Cloud Plans

| Plan | Protection |
|------|------------|
| Servers P2 | VMs, Arc servers, Defender for Endpoint |
| Containers | AKS, ACR, Arc-enabled K8s |
| SQL | Azure SQL, SQL on VMs |
| Storage | Malware scanning, sensitive data |
| Key Vault | Unusual access detection |
| App Service | Web app protection |
| CSPM | Attack path analysis |
