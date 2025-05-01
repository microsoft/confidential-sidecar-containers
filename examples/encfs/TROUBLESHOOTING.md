# Troubleshooting Guide for Deploying the Encrypted Filesystem Sidecar

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
Refer [here](https://github.com/microsoft/confidential-sidecar-containers/tree/main/examples/encfs#2-setup-azure-key-vault-and-generate-user-managed-identity) on how to setup the right role access for AKV/mHSM on the managed identity. 

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

When checking the log output of the ENCFS container, you may see the following error:

```text
err: pulling AKV response body failed: http response status equal to 403 Forbidden
```

Ensure that:

- the security policy is up-to-date by following these steps:
    1. re-run the policy generation tool whenever you update the ARM template
    2. update the "x-ms-sevsnpvm-hostdata" field in the importkeyconfig.json file with the updated security policy hash (output of step 1)
    3. re-run the importkey tool
- the managed identity has the correct permissions to the keyvault: *Key Vault Crypto Service Release User* role (previously *Key Vault Crypto Officer* and *Key Vault Crypto User*) if using AKV key vault or *Managed HSM Crypto Service Release User* role (previously *Managed HSM Crypto Officer* and *Managed HSM Crypto User*) for keys if using AKV managed HSM
- the MAA endpoints from both importkeyconfig.json and the base64 encoded "EncfsSideCarArgs" environment variable are correct and have no typos

## 404 Not Found Error

When checking the log output of the ENCFS container, you may see the following error:

```text
err: pulling AKV response body failed: http response status equal to 404 Not Found
```

Ensure that:

- the "kid" field in the importkeyconfig.json matches key "kid" field in the encfs-sidecar-args.json file that is base64-encoded in the "EncfsSideCarArgs" environment variable in the ARM template
- if the "kid" fields match, ensure such a key with the "kid" exists in the AKV/mHSM

## HTTP GET Failed Error

When checking the log output of the ENCFS container, you may see the following error:

```text
err: AKV post request failed: HTTP GET failed: Post "https://<mhsm-name>.managedhsm.azure.net/keys/<key-name>/release?api-version=7.3-preview": dial tcp: lookup <mhsm-name>.managedhsm.azure.net on 168.63.129.16:53: no such host
```

Ensure that:

- the name of the mHSM is correct in the encfs-sidecar-args.json file that is base64-encoded in the "EncfsSideCarArgs" environment variable in the ARM template and matches the name of the mHSM in the importkeyconfig.json file

The error message might also be the following: 

```text
attestation failed: Retrieving MAA token from MAA endpoint failed: maa post request failed: HTTP GET failed: Post "https://<maa-endpoint>/attest/SevSnpVM?api-version=2020-10-01": dial tcp: lookup <maa-endpoint> on <maa-endpoint-ip>: no such host
```

Ensure that: 

- the name of the MAA endpoint is correct in the encfs-sidecar-args.json file that is base64-encoded in the "EncfsSideCarArgs" environment variable in the ARM template and matches the name of the MAA endpoint in the importkeyconfig.json file
- make sure the MAA endpoint actually exists

## Input/Output Error

When checking the log output of the ENCFS container, you may see the following error:

```text
Failed to mount filesystems: failed to mount filesystem index 0: failed to mount filesystem: /dev/mapper/remote-crypt-0: input/output error
```

Ensure that:

- when uploading a blob to your Azure Storage Container, you set the "Blob type" to "Page blob" for Read-Write Filesystems

## Timed Out While Waiting for Encrypted Filesystem Error

When checking the log output of the ENCFS container, you may see the following error:

```text
Failed to mount filesystems: failed to mount filesystem index 0: failed to mount remote file: https://<storage-container-uri>.blob.core.windows.net/<container-name>/encfs.img: timed out while waiting for encrypted filesystem image: stat /tmp/remotefs2005737639/0/data: no such file or directory
```

Ensure that:

- the url of the uploaded blob is correctly copied into the [`encfs-sidecar-args.json`](encfs-sidecar-args.json#L5) file and before base64 encoding the contents of the file and copying to the [`EncfsSideCarArgs`](aci-arm-template.json#L36) field in the ARM template
- the managed identity on the ARM template has the correct role access to the storage account/container

## Cannot luksopen Error

When checking the log output the ENCFS container, you may see the error that says "Cannot luksopen". This happens when the released key cannot be used to decrypt remote file system.
One possible cause is that the oct key was imported as an rsa key. 

Ensure that: 

- the right `kty` on importkeyconfig.json is configured: currently the import key tool only supports `RSA-HSM` and `oct-HSM`

## Failed to Execute Cryptsetup Error

When checking the log output of the ENCFS container, you may see the following error:

```text
Failed to mount filesystems: failed to mount filesystem index 0: luksOpen failed: remote-crypt-0: failed to execute cryptsetup: # cryptsetup 2.6.1 processing "cryptsetup --debug -v luksOpen /tmp/remotefs4232314749/0/data remote-crypt-0 --key-file /tmp/remotefs4232314749/keyfile --integrity-no-journal --persistent"
```

followed by this error at the end of the log file:

```text
Command failed with code -2 (no permission or bad passphrase).
: exit status 2
```

Ensure that:

- read_write in [`encfs-sidecar-args.json`](encfs-sidecar-args.json#L7) is set to "true" for a read-write filesystem
- the "kid" field in the importkeyconfig.json matches key "kid" field in the encfs-sidecar-args.json file and is the key that was used to encrypt the blob being used as the encrypted filesystem
