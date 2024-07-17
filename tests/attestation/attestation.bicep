param location string
param registry string
param tag string
param ccePolicies object
param managedIDGroup string = resourceGroup().name
param managedIDName string
param attestationEndpoint string

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
      ccePolicy: ccePolicies.attestation
    }
    imageRegistryCredentials: [
      {
        server: registry
        identity: resourceId(managedIDGroup, 'Microsoft.ManagedIdentity/userAssignedIdentities', managedIDName)
      }
    ]
    volumes: [
      {
        name: 'uds'
        emptyDir: {}
      }
    ]
    containers: [
      {
        name: 'attestation-primary'
        properties: {
          image: '${registry}/attestation/primary:${empty(tag) ? 'latest': tag}'
          volumeMounts: [
            {
              name: 'uds'
              mountPath: '/mnt/uds'
            }
          ]
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
        name: 'attestation-sidecar'
        properties: {
          image: '${registry}/attestation/sidecar:${empty(tag) ? 'latest': tag}'
          ports: [
            {
              protocol: 'TCP'
              port: 8080
            }
          ]
          command: ['app', '-socket-address', '/mnt/uds/sock']
          environmentVariables: [
            {
              name: 'AZURE_ATTESTATION_ENDPOINT'
              value: attestationEndpoint
            }
          ]
          volumeMounts: [
            {
              name: 'uds'
              mountPath: '/mnt/uds'
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
