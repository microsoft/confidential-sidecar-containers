# Troubleshooting Guide for Deploying the SKR Sidecar

## 401 Unauthorized Error

When running the importkey tool, you may see the following error:

```
pulling AKV response body failed: http response status equal to 401 Unauthorized
```

Generate a new bearer token and copy it into the importkeyconfig.json.

```
az account get-access-token --resource https://managedhsm.azure.net
```

## 403 Forbidden Error

When checking the log output of the SKR container, you may see the following error:

```
err: pulling AKV response body failed: http response status equal to 403 Forbidden
```

Ensure that:

- the security policy is up-to-date by following these steps:
    1. re-run the policy generation tool whenever you update the ARM template
    2. update the "x-ms-sevsnpvm-hostdata" field in the importkeyconfig.json file with the updated security policy hash (output of step 1)
    3. re-run the importkey tool
- the managed identity has the correct permissions to the keyvault (*Key Vault Crypto Officer* and *Key Vault Crypto User* roles if using AKV key vault or *Managed HSM Crypto Officer* and *Managed HSM Crypto User* roles for keys if using AKV managed HSM)

## 404 Not Found Error

When checking the log output of the SKR container, you may see the following error:

```
err: pulling AKV response body failed: http response status equal to 404 Not Found
```

Ensure that:

- the "kid" field in the importkeyconfig.json matches "SkrClientKID" field in the ARM template

## HTTP GET Failed Error

When checking the log output of the SKR container, you may see the following error:

```
err: AKV post request failed: HTTP GET failed: Post "https://<mhsm-name>.managedhsm.azure.net/keys/<key-name>/release?api-version=7.3-preview": dial tcp: lookup <mhsm-name>.managedhsm.azure.net on 168.63.129.16:53: no such host
```

Ensure that:

- the name of the mHSM is correct in the ARM template and matches the name of the mHSM in the importkeyconfig.json file

## "CreateContainerRequest is blocked by policy" error (Confidential Containers in AKS Only)

If you are running the SKR container on Confidential Containers in AKS and the container pod does not run. Occasionally this could be caused by incorrect workload identity setup that results in empty environment variables that the container depends on. To debug, issue the following command: 

```bash
# This command describes the current status of the container pod
kubectl describe pod skr 
```
If the error is the following: 

```
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

Check the service account `azure.workload.identity/client-id` annotation value matches the obtained `USER_ASSIGNED_CLIENT_ID` value. If they match, check the following: 

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

Make sure the issuer matches the `AKS_OIDC_ISSUER` value obtained, the subject matches the service account (especially the namespace and service account name part), and the resourceGroup matches the one where the managed identity resides. If any one of the above items does not match, please follow the guide to re-enable workload identity. 

