# NOTE This example is for the Kata-based AKS preview
# Today the supported GA solution for Kubernetes is to use virtual nodes on Azure Confidential Instances (https://learn.microsoft.com/en-us/azure/container-instances/container-instances-virtual-nodes)


# Microsoft Secure Key Release (SKR) MAA Token Test on AKS Confidential Pods (i.e. based on Kata)

- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Get an MAA Token Workflow Step By Step](#secret-provisioning-workflow)
  - [1. Build the MAA test container](#1-build-the-maa-test-container)
  - [2. Update the YAML file](#2-update-the-yaml-file)
  - [3. Generate a Security Policy](#3-generate-a-security-policy)
  - [4. Deploy](#4-deploy)

## Introduction

This guide provides instructions on how to use the Secure Key Release (SKR) sidecar to get an attestation token from a MAA endpoint.

This requires the default HTTP endpoints in SKR.
Therefore, do NOT specify a port or any special environment variables, like in the [GRPC based example](../aks/skr-example-template.yaml).

## Prerequisites

- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli)
    - `confcom` Azure CLI extension (run `az extension add -n confcom`)
- `gettext` (for `envsubst`)
- A container registry (Azure Container Registry, Docker Hub, etc.)
- An AKS cluster set up with the Kata-based preview
    - Follow instructions here to get started: https://learn.microsoft.com/en-us/azure/aks/deploy-confidential-containers-default-policy

## Get an MAA Token Workflow Step By Step

### 1. Build the MAA test container

Review the contents of [Dockerfile.maa_test](../../../docker/skr/Dockerfile.maa_test) and update the attestation endpoint if you wish.

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

If you don't have a registry yet, you can follow the instructions in the [ACI README](../aci/README.md) to set one up.

Run Docker build on the files from the root directory, replacing <SKR_MAA_IMAGE> with the desired container name and version:

```bash
docker build -t <SKR_MAA_IMAGE> -f docker/skr/Dockerfile.maa_test .
```

Push the container images to your container registry:

```bash
docker push <SKR_MAA_IMAGE>
```

Replace the image value <SKR_MAA_IMAGE> in the [SKR MAA Comms YAML](skr-maa-comms-test.yaml) with the full registry plus container name of your image, i.e. `registry-name.azurecr.io/skr-maa-comms:1.0`.

### 2. Update the YAML file

If you updated the attestation endpoint in [Dockerfile.maa_test](../../../docker/skr/Dockerfile.maa_test), update the SkrSideCarArgs value to reflect that.
Base64 decode the current value, update, and base64 encode with padding before replacing the value in the YAML file.

Create an image pull secret (this example uses an Azure Container Registry) so that kubectl can access the images and update the YAML with the secret:

```bash
export ACR_SECRET=<secret-name>
kubectl create secret docker-registry $ACR_SECRET \
    --namespace <namespace> \
    --docker-server=<REGISTRY_NAME>.azurecr.io \
    --docker-username=<appId> \
    --docker-password=<password>

envsubst < skr-maa-comms-test.yaml > skr-maa-comms-test.yaml
```

### 3. Generate a Security Policy

The YAML file can be used directly to generate a security policy.
The following command generates a security policy and automatically injects it into the YAML file. 

```shell
az confcom katapolicygen -y skr-maa-comms.yaml
```

In order to shell into or use kubectl logs after deploying, you have to update the security policy manually.

Base64 decode the value in the template and find the following values:

```text
default ExecProcessRequest := false
default ReadStreamRequest := false
```

Set these values to true.

Also, find the list of allowed commands and add `/bin/sh` or `/bin/bash` to the list.
See this [issue resolution](https://github.com/Azure/azure-cli-extensions/issues/8432#issuecomment-2610440277) for more information.

Then, base64 encode with padding the updated security policy.
Replace the previous value in the YAML file with the updated policy.

### 4. Deploy

You can run an example deployment of a confidential pod with the `SKR` container and a `skr-maa-comms` container that invokes the MAA endpoint of the `SKR` container.
Use the [SKR MAA Comms YAML](skr-maa-comms-test.yaml) to deploy the pod.
Deploy the pod with kubectl using the following command:

```bash
kubectl apply -f skr-maa-comms-test.yaml
```

Issue the following command to get the logs from the `skr-maa-comms` container:

```bash
kubectl logs attestation-container -c maa-token-test
```

You should see a successfully returned MAA token in the output.