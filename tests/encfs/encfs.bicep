param location string
param registry string
param tag string
param ccePolicies object
param managedIDGroup string = resourceGroup().name
param managedIDName string

param sidecarArgsB64 string
var mount_point = '/mnt/remote'


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
      ccePolicy: ccePolicies.encfs
    }
    imageRegistryCredentials: [
      {
        server: registry
        identity: resourceId(managedIDGroup, 'Microsoft.ManagedIdentity/userAssignedIdentities', managedIDName)
      }
    ]
    volumes: [
      {
        name: 'encfs'
        emptyDir: {}
      }
    ]
    containers: [
      {
        name: 'primary'
        properties: {
          image: '${registry}/encfs/primary:${empty(tag) ? 'latest': tag}'
          ports: [
            {
              protocol: 'TCP'
              port: 8000
            }
          ]
          volumeMounts: [
            {
              name: 'encfs'
              mountPath: '/mnt/remote'
            }
          ]
          environmentVariables: [{name: 'ENCFS_MOUNT', value: '/mnt/remote'}]
          resources: {
            requests: {
              memoryInGB: 4
              cpu: 1
            }
          }
        }
      }
      {
        name: 'sidecar'
        properties: {
          image: '${registry}/encfs/sidecar:${empty(tag) ? 'latest': tag}'
          securityContext: {
            privileged: true
          }
          volumeMounts: [
            {
              name: 'encfs'
              mountPath: '/mnt/remote'
            }
          ]
          command: ['/encfs.sh']
          environmentVariables: [
            {
              name: 'EncfsSideCarArgs'
              value: sidecarArgsB64
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
