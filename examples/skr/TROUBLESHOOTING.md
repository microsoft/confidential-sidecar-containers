# Troubleshooting Guide for Deploying the SKR Sidecar

## 401 Unauthorized Error

When running the importkey tool, you may see the following error:

```
pulling AKV response body failed: http response status equal to 401 Unauthorized
```

To resolve this issue, generate a new bearer token and copy it into the importkeyconfig.json.

```
az account get-access-token --resource https://managedhsm.azure.net
```

## 403 Forbidden Error

When checking the log output of the SKR container, you may see the following error:

```
err: pulling AKV response body failed: http response status equal to 403 Forbidden
```

To resolve this issue, ensure that:

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

To resolve this issue, ensure that:

- the key name ("kid" field) in the importkeyconfig.json file matches the key name ("SkrClientKID") field in the ARM template

## HTTP GET Failed Error

When checking the log output of the SKR container, you may see the following error:

```
err: AKV post request failed: HTTP GET failed: Post "https://<mhsm-name>.managedhsm.azure.net/keys/<key-name>/release?api-version=7.3-preview": dial tcp: lookup <mhsm-name>.managedhsm.azure.net on 168.63.129.16:53: no such host
```

To resolve this issue, ensure that:

- the name of the mHSM is correct in the ARM template and matches the name of the mHSM in the importkeyconfig.json file
