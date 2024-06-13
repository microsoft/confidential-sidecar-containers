using './encfs.bicep'

// Image info
param registry='confidentialsidecars.azurecr.io'
param tag=''

// Deployment info
param location='westeurope'
param ccePolicies={
  encfs: ''
}
param managedIDName='cacisidecars'

param sidecarArgsB64=''
