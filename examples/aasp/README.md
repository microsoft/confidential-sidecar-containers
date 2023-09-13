# Microsoft Azure Attestion Secret Provisioning(AASP)


- [Introduction](#introduction)
- [Export Environment Variables](#export-environment-variables)
- [Prerequisites](#prerequisites)
- [Secret Provisioning Workflow Step By Step](#secret-provisioning-workflow-step-by-step)
    - [Step 1 Generate a private/public key pair and prepare for the key release policy](#step-1-generate-a-key-pair-and-prepare-for-the-key-release-policy)
    - [Step 2 Generate a wrapped secret using the public key using the aasp binary](#step-2-generate-a-wrapped-secret-using-the-public-key-using-the-aasp-binary)
    - [Step 3 Create a federated identity credential](#step-3-create-a-federated-identity-credential)
    - [Step 4 Running the AASP container in a TEE](#step-4-running-the-aasp-container-in-a-tee)
    - [Step 5 Unwrap the secret using grpcurl](#step-5-unwrap-the-secret-using-grpcurl)


# Introduction:

This guide provides instructions on how to perform secret provisioning using AASP container. 
The secret provisioning workflow involves generating a private/public key pair in mhsm, downloading the public key and generating a wrapped secret using AASP binary as a command line tool, and then unwrapping the secret using AASP as a GRPC service during runtime. 
This guide provides a step-by-step instruction for the steps above. By following these instructions, users can ensure that their secrets are securely stored and can be used by the application. 
This guide assumes a working mhsm and maa endpoint. See [prerequisites](#Prerequisites). 

# Export Environment Variables 

```bash
export AASP_IMAGE=<aasp-image-name>
export SAMPLE_UNWRAP_IMAGE=<sample-unwrap-image-name>
export RESOURCE_GROUP=<resource-group-name>
export USER_ASSIGNED_IDENTITY_NAME=<identity-name>
export LOCATION=<location>
export SUBSCRIPTION="$(az account show --query id --output tsv)"
export SERVICE_ACCOUNT_NAME=<service-account-name>
export SERVICE_ACCOUNT_NAMESPACE="default"
export FEDERATED_IDENTITY_CREDENTIAL_NAME=<federated-identity-credential-name>
```

# Prerequisites:
Before performing secret provisioning using AASP container, ensure that the following prerequisites are met:

Users must have a functioning mhsm to store the private key and its associated release policy. 
The release policy describes the conditions the key release request must meet in order for the mhsm to release the key. 

To set up a mhsm instance, follow instructions [here with Azure CLI](https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/quick-create-cli),
or through the [Azure portal](https://ms.portal.azure.com/#view/HubsExtension/BrowseResource/resourceType/Microsoft.KeyVault%2FmanagedHSMs). 
You can follow the installation instructions for Azure CLI [here](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli).

Users must have a working maa endpoint to interact with the mhsm.

In order to use grpcurl to call the exposed grpc APIs to unwrap secrets, users must build the following two images: 

1. The `AASP container` image that hosts grpc server. See [Dockerfile.build](../../docker/aasp/Dockerfile.build)
2. A `sample-unwrap` container image that has grpcurl installed and allows users to unwrap secrets. [Dockerfile.sample](../../docker/aasp/Dockerfile.sample)

These two images can be built using the existing Dockerfiles above. To build the images, make sure you are in the root of confidential-sidecar-containers repo and run the following commands:

```bash
docker build -t $AASP_IMAGE -f docker/aasp/Dockerfile.build . 
docker build -t $SAMPLE_UNWRAP_IMAGE -f docker/aasp/Dockerfile.sample .
```

We will use Azure Container Registry as an example here for deployment. Push the container image to your ACR. 


# Secret Provisioning Workflow:

## Step 1 generate a key pair and prepare for the key release policy:

This is a one time effort.
Once the key is created, it can be used to protect as many secrets as desired. 
The `setup-key-mhsm.sh` script creates a private/public key pair in the keyvault and a key release policy with the file name `keyname-release-policy.json`. 
The public key is then downloaded as `keyname-pub.pem` and a key info file is generated. 
Both the public key and the key info file are used for wrapping the secret. 
The script also assigns necessary access role(Managed HSM Crypto User) to the Managed Service Idenitty.
Depending on the operating system, make sure the end of line sequence(LF vs CRLF) is set correctly before running the script. 

`MANAGED_IDENTITY` has the following format: 
```
/subscriptions/<subscription-id>/resourceGroups/<resource_group_name>/providers/Microsoft.ManagedIdentity/<userAssignedIdentities>/msi
```
`<key-name>`: just the name of the key such as `samplekey`

`<mhsm>`: just the name of the mhsm instance without the `managedhsm.azure.net` part. 
For a mhsm instance with the full URL: `samplemhsm.managedhsm.azure.net`, the `mhsm` is just `samplemhsm`. 

```bash
# Create a managed identity for accessing MHSM. Note the Principle ID of the identity
az identity create -g $RESOURCE_GROUP -n $USER_ASSIGNED_IDENTITY_NAME | grep "id"
# The following two exported env vars are used by the setup-key-mhsm.sh script
export MANAGED_IDENTITY=<principle-id>
export MAA_ENDPOINT=<maa-endpoint> # Choose a MAA instance for the attestation service, e.g. sharedeus2.eus2.attest.azure.net

# Login 
az login 
# Set account context to the subscription where the mhsm resides 
az account set --subscription <subscription-name>
# change the access permissions to execute of the script
chmod +x setup-key-mhsm.sh 
# execute the script to generate key pair 
bash setup-key-mhsm.sh <key-name> <mhsm>
```

## Step 2 generate a wrapped secret using the public key using the aasp binary:

Build AASP binary first: 

```
go build -o aasp <path-to-aasp-main.go>
```

In the following example, the secret is stored in file [plaintext](plaintext). 
Assuming the name of the key we created in the above step is `testkey000`, we can generate a wrapped secret using the public key and store it in a file named wrapped(adjust the path to the key if necessary). 
This file will be used to unwrap the secret later. 
The wrapped file will be used to generate an argument that gets passed into grpcurl command to invoke the exposed gRPC APIs. 


```bash
aasp --infile plaintext --keypath ./testkey000 --outfile wrapped 
```

## Step 3 create a federated identity credential:

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
#Create the federated identity credential between the managed identity, service account issuer, and subject using the az identity federated-credential create command.
az identity federated-credential create --name ${FEDERATED_IDENTITY_CREDENTIAL_NAME} --identity-name ${USER_ASSIGNED_IDENTITY_NAME} --resource-group ${RESOURCE_GROUP} --issuer ${AKS_OIDC_ISSUER} --subject system:serviceaccount:${SERVICE_ACCOUNT_NAMESPACE}:${SERVICE_ACCOUNT_NAME}
```

## Step 4 running the AASP container in a TEE:
Use the AASP container as a GRPC service during runtime to unwrap the secret with the private key stored in mhsm. 
This step ensures that the private key is securely retrieved in AASP container and used for unwrapping the wrapped secret. 
Before unwrapping the secret, the AASP container image and the sample-unwrap container image with grpcurl command installed need to be built, see [prerequisites](#Prerequisites). 

You can run a sample deployment of a confidential pod with the `AASP` container and a `sample-unwrap` container that invokes the secret provisioning APIs of the `AASP` container. Use the following [sample pod yaml file](aasp-sample-template.yaml) to run the pod. But create an image pull secret first with the following command. 

```
export $ACR_SECRET=<secret-name>
kubectl create secret docker-registry $ACR_SECRET \
    --namespace <namespace> \
    --docker-server=<REGISTRY_NAME>.azurecr.io \
    --docker-username=<appId> \
    --docker-password=<password>

envsubst < aasp-sample-template.yaml > aasp-sample.yaml

kubectl apply -f aasp-sample.yaml 
```

Issue the following command to shell into the sample-unwrap container and issue grpcurl commands: 

```
kubectl exec --stdin --tty aasp-secret-provisioning -c sample-unwrap -- /bin/sh 

# This command lists the services exposed on 127.0.0.1:50000
grpcurl -v -plaintext 127.0.0.1:50000 list

# This command lists the exposed APIs under KeyProviderService on port 127.0.0.1:50000
grpcurl -v -plaintext 127.0.0.1:50000  list keyprovider.KeyProviderService

# Call the SayHello service. We use the SayHello method to test whether APIs under KeyProviderService can be reached 
grpcurl -v -plaintext -d '{"name":"Steven"}' 127.0.0.1:50000  keyprovider.KeyProviderService.SayHello

# Call the GetReport servie to get the SNP report in hex string format. Users can optionally provide `reportDataHexString` and the input will show under report data section of the SNP report. This is used for detecting replay attack. 
grpcurl -v -plaintext -d '{"reportDataHexString":""}' 127.0.0.1:50000  keyprovider.KeyProviderService.GetReport 

```

## Step 5 unwrap the secret using grpcurl. 

Make sure you are in the same directory as the `wrapped` file. 
Issue the following command in the sample-unwrapped container to test whether key can be released.

```
AAA=`printf aasp | base64 -w0`

ANNO=`cat wrapped`

REQ=`echo "{\"op\":\"keyunwrap\",\"keywrapparams\":{},\"keyunwrapparams\":{\"dc\":{\"Parameters\":{\"attestation-agent\":[\"${AAA}\"]}},\"annotation\":\"${ANNO}\"}}" | base64 -w0`

grpcurl -plaintext -d "{\"KeyProviderKeyWrapProtocolInput\":\"${REQ}\"}" 127.0.0.1:50000 keyprovider.KeyProviderService.UnWrapKey
```
Upon successful key release, you should see: 

```
Resolved method descriptor:
rpc UnWrapKey ( .keyprovider.keyProviderKeyWrapProtocolInput ) returns ( .keyprovider.keyProviderKeyWrapProtocolOutput );

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