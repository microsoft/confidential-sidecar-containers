
param name string
param location string = resourceGroup().location
param sku string = 'Standard_RAGRS'
param managedIdName string
param otherIds array = []


resource managedIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = {
  name: managedIdName
}

resource storageAccount 'Microsoft.Storage/storageAccounts@2021-04-01' = {
  name: '${name}storage'
  location: location
  kind: 'StorageV2'
  sku: {
    name: sku
  }
  properties: {
    accessTier: 'Hot'
    allowSharedKeyAccess: false
    minimumTlsVersion: 'TLS1_2'
  }
}


resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2021-06-01' = {
  parent: storageAccount
  name: 'default'
  properties: {}
}


resource blobContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2021-04-01' = {
  parent: blobService
  name: 'container'
  properties: {
    publicAccess: 'None'
  }
}


resource managedIdentityRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
    name: guid(storageAccount.id, 'MI', 'Storage Blob Data Contributor')
    properties: {
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')  // Storage Blob Data Contributor Role ID
      principalId: managedIdentity.properties.principalId
    }
    scope: resourceGroup()
  }


resource roleAssignments 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for id in otherIds: {
    name: guid(storageAccount.id, id, 'Storage Blob Data Contributor 2')
    properties: {
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')  // Storage Blob Data Contributor Role ID
      principalId: id
    }
    scope: resourceGroup()
  }
]


output blobEndpoint string = storageAccount.properties.primaryEndpoints.blob
