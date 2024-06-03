param name string
param managedIdName string = 'cacisidecars'
param location string = resourceGroup().location
param adminObjectIds array

resource managedIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = {
  name: managedIdName
}

resource managedHSM 'Microsoft.KeyVault/managedHSMs@2023-07-01' = {
  name: name
  location: location
  sku: {
    name: 'Standard_B1'
    family: 'B'
  }
  properties: {
    initialAdminObjectIds: union([managedIdentity.properties.principalId], adminObjectIds)
    tenantId: subscription().tenantId
  }
}

output admins array = managedHSM.properties.initialAdminObjectIds
output name string = managedHSM.name
