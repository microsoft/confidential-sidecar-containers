using './skr.bicep'

// Image info
param registry='confidentialsidecars.azurecr.io'
param tag=''
param skrImage=readEnvironmentVariable('SKR_IMAGE', '')

// Deployment info
param location='westeurope'
param ccePolicies={
  skr: ''
}
param managedIDName='cacisidecars'
