# NOTE This example is for the Kata based AKS preview
# Today the supported GA solution for Kubernetes is to use virtual nodes on Azure Confidential Instances (https://learn.microsoft.com/en-us/azure/container-instances/container-instances-virtual-nodes)


# Microsoft Secure Key Release (SKR) AKS Confidential Pods (i.e. based on Kata) Example

- [Introduction](#introduction)
- [Export Environment Variables](#export-environment-variables)
- [Secret Provisioning Workflow Step By Step](#secret-provisioning-workflow)
  - [1. Create a mHSM Instance](#1-create-a-mhsm-instance)
  - [2. Obtain an Attestation Endpoint](#2-obtain-an-attestation-endpoint)
  - [3. Generate a Key Pair](#3-generate-a-key-pair)
  - [4. Generate a Wrapped Secret](#4-generate-a-wrapped-secret)
  - [5. Create a Federated Credential Identity](#5-create-a-federated-credential-identity)
  - [6. Build Required Container Images](#6-build-required-container-images)
  - [7. Running the SKR Container in a TEE](#7-running-the-skr-container-in-a-tee)
  - [8. Unwrap the Secret Using grpcurl](#8-unwrap-the-secret-using-grpcurl)

## Introduction

This guide provides instructions on how to perform secret provisioning in AKS using the SKR container.
By following these instructions, users can ensure that their secrets are securely stored and can be used by their applications.

Note: These instructions assume the usage of an Azure Key Vault and Microsoft Azure Attestation Endpoint, however the steps can be adapted for other key vaults and attestation services.

## Export Environment Variables

```bash
export SKR_IMAGE=<skr-image-name>
export EXAMPLE_UNWRAP_IMAGE=<example-unwrap-image-name>
export RESOURCE_GROUP=<resource-group-name>
export USER_ASSIGNED_IDENTITY_NAME=<identity-name>
export LOCATION=<location>
export SUBSCRIPTION="$(az account show --query id --output tsv)"
export SERVICE_ACCOUNT_NAME=<service-account-name>
export SERVICE_ACCOUNT_NAMESPACE="default"
export FEDERATED_CREDENTIAL_IDENTITY_NAME=<federated-credential-identity-name>
```

## Secret Provisioning Workflow

### 1. Create a mHSM Instance

Users must have a functioning mHSM to store the private key and its associated release policy.
The release policy describes the conditions the key release request must meet in order for the mhsm to release the key.

To set up a mHSM instance, follow the instructions [here with Azure CLI](https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/quick-create-cli), or through the [Azure portal](https://ms.portal.azure.com/#view/HubsExtension/BrowseResource/resourceType/Microsoft.KeyVault%2FmanagedHSMs).
You can follow the installation instructions for Azure CLI [here](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli).

### 2. Obtain An Attestation Endpoint

Below are the MAA endpoints (as of April 2025) for the four regions in which Confidential Containers on AKS is currently available.

- East US: sharedeus.eus.attest.azure.net
- West US: sharedwus.wus.attest.azure.net
- North Europe: sharedneu.neu.attest.azure.net
- West Europe: sharedweu.weu.attest.azure.net

You can check the MAA endpoint for a given Azure region by the following command: 

```pwsh
Get-AzAttestationDefaultProvider -Location "westus" | Format-Table -Property Location, AttestUri
```

To list the MAA endpoints for every Azure region:

```pwsh
(Get-AzAttestationDefaultProvider).Value | Sort-Object Location | Format-Table -Property Location, AttestUri
```

### 3. Generate a Key Pair

This is a one time effort.
Once the key is created, it can be used to protect as many secrets as desired.

The `setup-key-mhsm.sh` script creates a private/public key pair in the keyvault and a key release policy with the file name `<keyname>-release-policy.json`.
The public key is then downloaded as `<keyname>-pub.pem` and `<keyname>-info.json`, a key info file, is generated and stored locally.
Both the public key and the key info file are used for wrapping the secret.

If using an already existing key pair, create the key info file in the same directory as the key and with the name `<keyname>-info.json` and the following format:

```json
{
  "public_key_path": "/path/to/public/key-file",
  "kms_endpoint": "<mhsm-endpoint>",
  "attester_endpoint": "<MAA-endpoint>"
}
```

Note: The endpoints do not include the `https://` prefix.

The script also assigns the necessary access role (Managed HSM Crypto User) to the Managed Identity.
Depending on the operating system, make sure the end of line sequence(LF vs CRLF) is set correctly before running the script.

`MANAGED_IDENTITY` has the following format:

`/subscriptions/<subscription-id>/resourceGroups/<resource_group_name>/providers/Microsoft.ManagedIdentity/<userAssignedIdentities>/msi`

`<key-name>`: just the name of the key such as `examplekey`

`<mhsm>`: just the name of the mhsm instance without the `managedhsm.azure.net` part.
For a mhsm instance with the full URL: `examplemhsm.managedhsm.azure.net`, the `mhsm` is just `examplemhsm`.

```bash
# Create a managed identity for accessing MHSM. Note the Principle ID of the identity
az identity create -g $RESOURCE_GROUP -n $USER_ASSIGNED_IDENTITY_NAME | grep "id"
# The following two exported env vars are used by the setup-key-mhsm.sh script
export MANAGED_IDENTITY=<principle-id>
export MAA_ENDPOINT=<maa-endpoint> # Choose a MAA instance for the attestation service, e.g. sharedeus.eus.attest.azure.net

# Login
az login
# Set account context to the subscription where the mhsm resides
az account set --subscription <subscription-name>
# change the access permissions to execute of the script
chmod +x setup-key-mhsm.sh
# execute the script to generate key pair
bash setup-key-mhsm.sh <key-name> <mhsm>
```

### 4. Generate a Wrapped Secret

Build the SKR binary first:

```bash
go build -o skr ./cmd/skr/main.go
```

In the following example, the secret is stored in file [plaintext](plaintext).
Assuming the name of the key we created in the above step is `testkey000`, we can generate a wrapped secret using the public key and store it in a file named wrapped (adjust the path to the key if necessary).
This file will be used to unwrap the secret later.
The wrapped file will be used to generate an argument that gets passed into grpcurl command to invoke the exposed gRPC APIs.

```bash
skr --infile plaintext --keypath ./testkey000 --outfile wrapped
```

Note: The skr tool assumes that the key info file is in the same directory as the key with the name `<keyname>-info.json`, as seen in [Step 3. Generate a Key Pair](#3-generate-a-key-pair).

### 5. Create a Federated Credential Identity

```bash
export AKS_OIDC_ISSUER="$(az aks show -n clusterName -g "${RESOURCE_GROUP}" --query "oidcIssuerProfile.issuerUrl" -otsv)"

export USER_ASSIGNED_CLIENT_ID="$(az identity show --resource-group "${RESOURCE_GROUP}" --name "${USER_ASSIGNED_IDENTITY_NAME}" --query 'clientId' -otsv)"

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  annotations:
    azure.workload.identity/client-id: ${USER_ASSIGNED_CLIENT_ID}
  name: ${SERVICE_ACCOUNT_NAME}
  namespace: ${SERVICE_ACCOUNT_NAMESPACE}
EOF
# Create the federated credential identity between the managed identity, service account issuer, and subject using the az identity federated-credential create command.
az identity federated-credential create --name ${FEDERATED_CREDENTIAL_IDENTITY_NAME} --identity-name ${USER_ASSIGNED_IDENTITY_NAME} --resource-group ${RESOURCE_GROUP} --issuer ${AKS_OIDC_ISSUER} --subject system:serviceaccount:${SERVICE_ACCOUNT_NAMESPACE}:${SERVICE_ACCOUNT_NAME}
```

### 6. Build Required Container Images

In order to use grpcurl to call the exposed grpc APIs to unwrap secrets, users must build the following two images:

1. The `SKR container` image that hosts grpc server.
See [Dockerfile.build](../../../docker/skr/Dockerfile.skr)
2. A `example-unwrap` container image that has grpcurl installed and allows users to unwrap secrets.
See [Dockerfile.example](../../../docker/skr/Dockerfile.example)

To build the images, make sure you are in the root of confidential-sidecar-containers repo and run the following commands:

```bash
docker build -t $SKR_IMAGE -f docker/skr/Dockerfile.skr .
docker build -t $EXAMPLE_UNWRAP_IMAGE -f docker/skr/Dockerfile.example .
```

Push the container images to your container registry.

### 7. Running the SKR Container in a TEE

Use the SKR container as a gRPC service during runtime to unwrap the secret with the private key stored in mHSM.
This step ensures that the private key is securely retrieved in the SKR container and used for unwrapping the wrapped secret.
Note that gRPC is off by default and the environment variable `ServerType` can be set to `grpc` to enable the gRPC server and disable the HTTP server.
An example `Port` value for gRPC is `50000`.

You can run an example deployment of a confidential pod with the `SKR` container and a `example-unwrap` container that invokes the secret provisioning APIs of the `SKR` container.
Use the [example pod yaml file](skr-example-template.yaml) to deploy the pod.
First, create an image pull secret (this example uses an Azure Container Registry) then deploy the pod with kubectl using the following command:

```bash
export ACR_SECRET=<secret-name>
kubectl create secret docker-registry $ACR_SECRET \
    --namespace <namespace> \
    --docker-server=<REGISTRY_NAME>.azurecr.io \
    --docker-username=<appId> \
    --docker-password=<password>

envsubst < skr-example-template.yaml > skr-example.yaml

kubectl apply -f skr-example.yaml
```

Issue the following command to shell into the example-unwrap container and issue grpcurl commands:

```bash
kubectl exec --stdin --tty skr-secret-provisioning -c example-unwrap -- /bin/sh

# This command lists the services exposed on 127.0.0.1:50000
grpcurl -v -plaintext 127.0.0.1:50000 list

# This command lists the exposed APIs under KeyProviderService on port 127.0.0.1:50000
grpcurl -v -plaintext 127.0.0.1:50000  list key_provider.KeyProviderService

# Call the SayHello service. We use the SayHello method to test whether APIs under KeyProviderService can be reached
grpcurl -v -plaintext -d '{"name":"This is a GRPC test!"}' 127.0.0.1:50000  key_provider.KeyProviderService.SayHello

# Call the GetReport service to get the SNP report in hex string format. Users can optionally provide `reportDataHexString` and the input will show under report data section of the SNP report. This is used for detecting a replay attack.
grpcurl -v -plaintext -d '{"reportDataHexString":""}' 127.0.0.1:50000  key_provider.KeyProviderService.GetReport

```

### 8. Unwrap the Secret Using grpcurl

While shelled into the example-unwrap container, make sure you are in the same directory as the `wrapped` file.
Issue the following command to test whether the key can be released.

```bash
AAA=`printf skr | base64 -w0`

ANNO=`cat wrapped`

REQ=`echo "{\"op\":\"keyunwrap\",\"keywrapparams\":{},\"keyunwrapparams\":{\"dc\":{\"Parameters\":{\"attestation-agent\":[\"${AAA}\"]}},\"annotation\":\"${ANNO}\"}}" | base64 -w0`

grpcurl -plaintext -d "{\"KeyProviderKeyWrapProtocolInput\":\"${REQ}\"}" 127.0.0.1:50000 key_provider.KeyProviderService.UnWrapKey
```

Upon successful key release, you should see:

```json
Resolved method descriptor:
rpc UnWrapKey ( .key_provider.keyProviderKeyWrapProtocolInput ) returns ( .key_provider.keyProviderKeyWrapProtocolOutput );

Request metadata to send:
(empty)

Response headers received:
content-type: application/grpc

Response contents:
{
  "KeyProviderKeyWrapProtocolOutput": "eyJrZXl3cmFwcmVzdWx0cyI6eyJhbm5vdGF0aW9uIjpudWxsfSwia2V5dW53cmFwcmVzdWx0cyI6eyJvcHRzZGF0YSI6IlQyTmxZVzV6SUdGeVpTQm1kV3hzSUc5bUlIZGhkR1Z5RFFwSWIzSnpaWE1nYUdGMlpTQTBJR3hsWjNNTkNnPT0ifX0="
}
```

Base64 decode the result to see the encrypted secret.

```json
{"keywrapresults":{"annotation":null},"keyunwrapresults":{"optsdata":"T2NlYW5zIGFyZSBmdWxsIG9mIHdhdGVyDQpIb3JzZXMgaGF2ZSA0IGxlZ3MNCg=="}}
```

Base64 decode the `optsdata` field to see the secret (the contents of the plaintext file).

```
Oceans are full of water
Horses have 4 legs
```
