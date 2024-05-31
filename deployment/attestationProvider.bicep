param name string
param location string = resourceGroup().location

resource attestationProvider 'Microsoft.Attestation/attestationProviders@2021-06-01' = {
  name: name
  location: location
  properties: {}
}
