using './attestation.bicep'

// Image info
param registry='confidentialsidecars.azurecr.io'
param tag=''

// Deployment info
param location='westeurope'
param ccePolicies={
  attestation: ''
}
param managedIDName='cacisidecars'
param attestationEndpoint='https://confidentialsidecars.weu.attest.azure.net'
