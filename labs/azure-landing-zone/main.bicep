targetScope = 'tenant'

@description('Stable management group identifier for the organization landing-zone root.')
param rootManagementGroupId string

@description('Display name for the organization landing-zone root.')
param rootDisplayName string

@description('Azure region required for tenant-scope deployment metadata.')
param deploymentLocation string = 'canadacentral'

@description('Locations audited by the sample baseline policy.')
param allowedLocations array = [
  'canadacentral'
  'canadaeast'
]

resource root 'Microsoft.Management/managementGroups@2023-04-01' = {
  name: rootManagementGroupId
  properties: {
    displayName: rootDisplayName
  }
}

resource platform 'Microsoft.Management/managementGroups@2023-04-01' = {
  name: '${rootManagementGroupId}-platform'
  properties: {
    displayName: 'Platform'
    details: {
      parent: {
        id: root.id
      }
    }
  }
}

resource landingZones 'Microsoft.Management/managementGroups@2023-04-01' = {
  name: '${rootManagementGroupId}-landing-zones'
  properties: {
    displayName: 'Landing zones'
    details: {
      parent: {
        id: root.id
      }
    }
  }
}

resource sandbox 'Microsoft.Management/managementGroups@2023-04-01' = {
  name: '${rootManagementGroupId}-sandbox'
  properties: {
    displayName: 'Sandbox'
    details: {
      parent: {
        id: root.id
      }
    }
  }
}

module baseline 'modules/policy-baseline.bicep' = {
  name: 'landing-zone-audit-baseline'
  scope: managementGroup(rootManagementGroupId)
  params: {
    allowedLocations: allowedLocations
    assignmentLocation: deploymentLocation
  }
  dependsOn: [
    root
  ]
}

output managementGroupIds object = {
  root: root.id
  platform: platform.id
  landingZones: landingZones.id
  sandbox: sandbox.id
}
