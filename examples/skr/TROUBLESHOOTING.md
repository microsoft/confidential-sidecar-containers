# Troubleshooting Guide for Deploying the Secure Key Release Sidecar

## 401 Unauthorized Error

When running the importkey tool, you may see the following error:

```text
pulling AKV response body failed: http response status equal to 401 Unauthorized
```

Generate a new bearer token and copy it into the importkeyconfig.json.

```bash
az account get-access-token --resource https://managedhsm.azure.net
```

If the http response status is still 401 Unauthorized, check whether the identity you logged in has access to the AKV/mHSM you tried to import keys into.
Refer [here](https://github.com/microsoft/confidential-sidecar-containers/tree/main/examples/skr/aci#2-generate-user-managed-identity) on how to setup the right role access for AKV/mHSM on the managed identity. 

## 400 Bad Request Error 

```
pulling AKV response body failed: {"error":{"code":"BadParameter","message":"JSON Web Key: k property of oct key is too large, maximum size is 64 (Activity ID: 41c*****d6)"}}: http response status equal to 400 Bad Request

```

This might indicate that you tried to import an rsa key as an oct key or that the `kty` on importkeyconfig.json is inconsistent with the actual key you tried to import.

## Key not supported Error 

```
Key not supported
```

This means the `kty` on `importkeyconfig.json` is wrong.
Currently the import key tool only supports two types of keys: `RSA-HSM` and `oct-HSM`. 

## 403 Forbidden Error

When checking the log output of the SKR container, you may see the following error:

```text
err: pulling AKV response body failed: http response status equal to 403 Forbidden
```

Ensure that:

- the security policy is up-to-date by following these steps:
    1. re-run the policy generation tool whenever you update the ARM template
    2. update the "x-ms-sevsnpvm-hostdata" field in the importkeyconfig.json file with the updated security policy hash (output of step 1)
    3. re-run the importkey tool
- the managed identity has the correct permissions to the keyvault: *Key Vault Crypto Service Release User* role (previously *Key Vault Crypto Officer* and *Key Vault Crypto User*) if using AKV key vault or *Managed HSM Crypto Service Release User* role (previously *Managed HSM Crypto Officer* and *Managed HSM Crypto User*) for keys if using AKV managed HSM
- the MAA endpoints from both importkeyconfig.json and the `SkrClientMAAEndpoint` are correct and have no typos 

## 404 Not Found Error

When checking the log output of the SKR container, you may see the following error:

```text
err: pulling AKV response body failed: http response status equal to 404 Not Found
```

Ensure that:

- the "kid" field in the importkeyconfig.json matches "SkrClientKID" field in the ARM template
- if the "kid" fields match, ensure such a key with the "kid" exists in the AKV/mHSM

## HTTP GET Failed Error

When checking the log output of the SKR container, you may see the following error:

```text
err: AKV post request failed: HTTP GET failed: Post "https://<mhsm-name>.managedhsm.azure.net/keys/<key-name>/release?api-version=7.3-preview": dial tcp: lookup <mhsm-name>.managedhsm.azure.net on 168.63.129.16:53: no such host
```

Ensure that:

- the name of the mHSM is correct in the ARM template or key-info.json (for AKS) and matches the name of the mHSM in the importkeyconfig.json file

The error message might also be the following: 

```text
attestation failed: Retrieving MAA token from MAA endpoint failed: maa post request failed: HTTP GET failed: Post "https://<maa-endpoint>/attest/SevSnpVM?api-version=2020-10-01": dial tcp: lookup <maa-endpoint> on <maa-endpoint-ip>: no such host
```

Ensure that: 

- the value of `SkrClientMAAEndpoint` on the ARM template is correct and matches the name of the MAA endpoint in the importkeyconfig.json file
- make sure the MAA endpoint actually exists

## "CreateContainerRequest is blocked by policy" error (Confidential Containers in AKS Only)

If you are running the SKR container on Confidential Containers in AKS and the container pod does not run.
Occasionally this could be caused by incorrect workload identity setup that results in empty environment variables that the container depends on.
To debug, issue the following command:

```bash
# This command describes the current status of the container pod
kubectl describe pod skr 
```

If the error is the following:

```text
Failed to create pod sandbox: rpc error: code = Unknown desc = failed to create containerd task: failed to create shim task: "CreateContainerRequest is blocked by policy": unknown
```

Issue the following commands to check the workload identity is properly enabled where the pod containing the SKR container is running:

```bash
# Obtain the client id of the managed identity. 
# USER_ASSIGNED_IDENTITY_NAME is the name of the managed identity used for accessing key vault 
# RESOURCE_GROUP is the resource group name where the managed identity resides 
export USER_ASSIGNED_CLIENT_ID="$(az identity show --resource-group "${RESOURCE_GROUP}" --name "${USER_ASSIGNED_IDENTITY_NAME}" --query 'clientId' -otsv)" 
# Obtain the service account detail
kubectl get sa <service-account-name> -n <skr-container-pod-namespace> -o yaml 
```

Check the service account `azure.workload.identity/client-id` annotation value matches the obtained `USER_ASSIGNED_CLIENT_ID` value.
If they match, check the following:

```bash
# Obtain the AKS_OIDC_ISSUER. Replace CLUSTER_NAME and RESOURCE_GROUP with the name of the cluster skr is run and the resource group the cluster resides 
export AKS_OIDC_ISSUER="$(az aks show -n "${CLUSTER_NAME}" -g "${RESOURCE_GROUP}" --query "oidcIssuerProfile.issuerUrl" -otsv)"
# Obtain the federated identity detail 
# FEDERATED_IDENTITY_NAME is the name of the federated identity created previously before skr is initially run 
az identity federated-credential show --resource-group "${RESOURCE_GROUP}" -n "${FEDERATED_IDENTITY_NAME}" --identity-name "${USER_ASSIGNED_IDENTITY_NAME}"
```

Once you have the federated identity detail, it should look something like this:

```json
{
  "audiences": [
    "api://AzureADTokenExchange"
  ],
  "id": "/subscriptions/84**********e9bdf8/resourcegroups/resourcegroupname/providers/Microsoft.ManagedIdentity/userAssignedIdentities/identityname/federatedIdentityCredentials/myFedIdentity",
  "issuer": "https://eastus.oic.prod-aks.azure.com/72f988**********011db47/ddfa**********2d5/",
  "name": "myFedIdentity",
  "resourceGroup": "resourcegroupname",
  "subject": "system:serviceaccount:kafka:workload-identity-sa",
  "systemData": null,
  "type": "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials"
}
```

Make sure the issuer matches the `AKS_OIDC_ISSUER` value obtained, the subject matches the service account (especially the namespace and service account name part), and the resourceGroup matches the one where the managed identity resides.
If any one of the above items does not match, please follow the guide to re-enable workload identity.
