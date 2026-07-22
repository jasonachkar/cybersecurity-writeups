targetScope = 'managementGroup'

param allowedLocations array
param assignmentLocation string

resource allowedLocationsDefinition 'Microsoft.Authorization/policyDefinitions@2023-04-01' = {
  name: 'audit-allowed-locations'
  properties: {
    displayName: 'Audit resources outside reviewed locations'
    description: 'Teaching policy: audit, rather than deny, while teams inventory exemptions and validate impact.'
    policyType: 'Custom'
    mode: 'Indexed'
    metadata: {
      category: 'Landing zone lab'
      version: '1.0.0'
    }
    parameters: {
      allowedLocations: {
        type: 'Array'
        metadata: {
          displayName: 'Allowed locations'
        }
      }
    }
    policyRule: {
      if: {
        allOf: [
          {
            field: 'location'
            exists: 'true'
          }
          {
            field: 'location'
            notIn: '[parameters(\'allowedLocations\')]'
          }
        ]
      }
      then: {
        effect: 'audit'
      }
    }
  }
}

resource allowedLocationsAssignment 'Microsoft.Authorization/policyAssignments@2024-04-01' = {
  name: 'audit-allowed-locations'
  location: assignmentLocation
  properties: {
    displayName: 'Audit resources outside reviewed locations'
    description: 'Lab assignment begins in audit mode. Promote only after impact analysis, exemption ownership, and rollback validation.'
    policyDefinitionId: allowedLocationsDefinition.id
    enforcementMode: 'Default'
    parameters: {
      allowedLocations: {
        value: allowedLocations
      }
    }
  }
}

output policyDefinitionId string = allowedLocationsDefinition.id
output policyAssignmentId string = allowedLocationsAssignment.id
