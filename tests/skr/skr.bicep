param location string
param registry string
param tag string
param ccePolicies object
param managedIDGroup string = resourceGroup().name
param managedIDName string

resource containerGroup 'Microsoft.ContainerInstance/containerGroups@2023-05-01' = {
  name: deployment().name
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${resourceId(managedIDGroup, 'Microsoft.ManagedIdentity/userAssignedIdentities', managedIDName)}': {}
    }
  }
  properties: {
    osType: 'Linux'
    sku: 'Confidential'
    restartPolicy: 'Never'
    ipAddress: {
      ports: [
        {
          protocol: 'TCP'
          port: 8000
        }
      ]
      type: 'Public'
    }
    confidentialComputeProperties: {
      ccePolicy: ccePolicies.skr
    }
    imageRegistryCredentials: [
      {
        server: registry
        identity: resourceId(managedIDGroup, 'Microsoft.ManagedIdentity/userAssignedIdentities', managedIDName)
      }
    ]
    containers: [
      {
        name: 'proxy'
        properties: {
          image: '${registry}/skr/proxy:${empty(tag) ? 'latest': tag}'
          ports: [
            {
              protocol: 'TCP'
              port: 8000
            }
          ]
          resources: {
            requests: {
              memoryInGB: 4
              cpu: 1
            }
          }
        }
      }
      {
        name: 'http-sidecar'
        properties: {
          image: '${registry}/skr/sidecar:${empty(tag) ? 'latest': tag}'
          ports: [
            {
              protocol: 'TCP'
              port: 8080
            }
          ]
          resources: {
            requests: {
              memoryInGB: 4
              cpu: 1
            }
          }
        }
      }
      {
        name: 'grpc-sidecar'
        properties: {
          image: '${registry}/skr/sidecar:${empty(tag) ? 'latest': tag}'
          environmentVariables: [
            {
              name: 'ServerType'
              value: 'grpc'
            }
            {
              name: 'Port'
              value: '50000'
            }
          ]
          ports: [
            {
              protocol: 'TCP'
              port: 50000
            }
          ]
          resources: {
            requests: {
              memoryInGB: 4
              cpu: 1
            }
          }
        }
      }
    ]
  }
}

output ids array = [containerGroup.id]
