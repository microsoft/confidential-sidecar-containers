# Encrypted filesystem container example

## Table of Contents

- [Policy generation](#policy-generation)
- [Step by Step Example](#step-by-step-example)

### Policy generation

Deploying a confidential container group requires generating a security policy that restricts what containers can run within the container group.
To generate security policies, install the Azure `confcom` CLI extension by following the instructions [here](https://github.com/Azure/azure-cli-extensions/tree/main/src/confcom/azext_confcom#microsoft-azure-cli-confcom-extension-examples).

The ARM template can be used directly to generate a security policy.
The following command generates a security policy and automatically injects it into the template.
Make sure `--debug-mode` option is included so that the generated policy allows shelling into container to see the released key in this example. Note this should only be used for debugging and not recommended for production systems.
We are going to include this option since this is an example.

```bash
az confcom acipolicygen -a aci-skr-arm-template.json --debug-mode
```

The ARM template file includes two entries: (i) encrypted filesystem sidecar container which enables the `/encfs.sh` as entry point command and the environment variable *EncfsSideCarArgs* used by the script, and (ii) an application container which enables a while loop command as entry point command.

### Step by Step Example

This example is made to be run on Linux/WSL.
Also make sure the line endings in the scripts used in this example are set to LF instead of CRLF.
However, the import key tool is available in both Linux and Windows.
The MAA endpoint is the value of env var [Authority Endpoint](encfs-sidecar-args.json#L12).
See "obtain an attestation endpoint" section on how to get this endpoint.
The managed HSM instance endpoint corresponds to [AKV Endpoint](encfs-sidecar-args.json#L15).
We will also define and import a key into the managed HSM as shown in [`importkeyconfig.json`](importkeyconfig.json#L2).
See "Setup Azure Key Vault and Generate User Managed Identity" section on how to obtain the mHSM endpoint.

#### 1. Obtain an Attestation Endpoint

If you don't already have a valid attestation endpoint, create a [Microsoft Azure Attestation](https://learn.microsoft.com/en-us/azure/attestation/overview) endpoint to author the attestation token and run the following command to get the endpoint value:

```bash
az attestation show --name "<ATTESTATION PROVIDER NAME>" --resource-group "<RESOURCE GROUP>"
```

Copy the AttestURI endpoint value (sans https://) to the [Attestation Authority endpoint](importkeyconfig.json#L6) in `importkeyconfig.json` and to [Attestation Authority endpoint](encfs-sidecar-args.json#L12) in `encfs-sidecar-args.json`.

#### 2. Setup Azure Key Vault and Generate User Managed Identity

The user needs to instantiate an Azure Key Vault resource that supports storing keys in an mHSM: a [Premium vault](https://learn.microsoft.com/en-us/azure/key-vault/general/overview) or an [mHSM resource](https://docs.microsoft.com/en-us/azure/key-vault/managed-hsm/overview).

After setting up an Azure Key Vault resource, generate a user-assigned managed identity that will be attached to the container group so that the containers have the correct access permissions to Azure services and resources.
The managed identity needs *Key Vault Crypto Service Release User* role (previously *Key Vault Crypto Officer* and *Key Vault Crypto User*) if using AKV key vault or *Managed HSM Crypto Service Release User* role (previously *Managed HSM Crypto Officer* and *Managed HSM Crypto User*) for keys if using AKV managed HSM.
More information about creating identities can be found [here.](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/)

If you already have a user-assigned managed identity with the appropriate access permissions, run the following command to list the managed identities for a resource group:

```bash
az identity list -g <RESOURCE GROUP>
```

Or you can use the following command if you know the name of the managed identity and the resource group:

```bash
az identity show -g <RESOURCE GROUP> -n <MANAGED IDENTITY NAME>
```

Replace [managed-identity-with-right-permissions-to-key-vault](aci-arm-template.json#L22) of `aci-arm-template.json` with the identity ID.

#### 3. Populate Image Registry Credentials

Update the [image registry credentials](aci-arm-template.json?plain=1#L94) on the ARM template in order to access a private container registry.
The credential could be either a managed identity or username/password.
This section is not needed for public images.
If the credential needs to be a managed identity, the managed identity needs to be granted `AcrPull role` to the private images.
See this [doc](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-authentication-managed-identity?tabs=azure-cli#example-1-access-with-a-user-assigned-identity).

#### 4. Obtain the AAD token

The AAD token with permission to AKV/mHSM can be obtained with the following command:

```bash
az account get-access-token --resource https://managedhsm.azure.net
```

#### 5. Fill in Key Information

Replace [AAD token](importkeyconfig.json#L11) and [ENCFS AKV endpoint](importkeyconfig.json#L9) in `importkeyconfig.json` with the output accessToken and the mHSM endpoint.
Replace [ENCFS AKV endpoint](encfs-sidecar-args.json#L15) in `enfcs-sidecar-args.json` with the mHSM endpoint.

After setting up an Azure Key Vault resource, fill in the `importkeyconfig.json` file with the name of the key to be created and imported into the key vault [Key name](importkeyconfig.json#L3).
Additionally, fill in `encfs-sidecar-args.json` with the name of the key to be created and imported into the key vault [Key name](encfs-sidecar-args.json#L9).

Additionally, fill in the optional [key derivation](importkeyconfig.json#L14) for RSA keys and [Key type: `RSA-HSM` or `oct-HSM`](importkeyconfig.json#L4) fields or remove these fields from the `importkeyconfig.json` file.
Fill in [key derivation](encfs-sidecar-args.json#L18) and [Key type: `RSA-HSM` or `oct-HSM`](encfs-sidecar-args.json#L10) in `encfs-sidecar-args.json` or remove them as well as well.

#### 6. Create Azure Storage Container

The user needs to instantiate an [Azure Storage Container](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-create?toc=%2Fazure%2Fstorage%2Fblobs%2Ftoc.json&bc=%2Fazure%2Fstorage%2Fblobs%2Fbreadcrumb%2Ftoc.json&tabs=azure-portal) onto which the encrypted filesystem will be uploaded.
Obtain the url of the uploaded encrypted file system image.
You need to know the name of the container under which the file system gets uploaded.
The full url should be in the following format:

```text
https://<azure-storage-account>.blob.core.windows.net/<container-name>/encfs.img
```

Fill in the [azure url](encfs-sidecar-args.json#L5) in `encfs-sidecar-args.json`.
At this point, the `encfs-sidecar-args.json` file should be completely filled out and the user needs to base64 encode the contents and copy it to [`EncfsSideCarArgs`](aci-arm-template.json#L36).

#### 7. Generate Security Policy

Configure the [LogFile](aci-arm-template.json#L39) and [LogLevel](aci-arm-template.json#L43) fields on the `aci-arm-template.json`.
eg. `log.txt` as the value of [LogFile] so that users can cat `log.txt` at the root of encrypted-filesystem-sidecar-container container.
The default logging is `warning` level. At this point, the `aci-arm-template.json` file should be filled out except for the `ccePolicy` field.
Set the value of the `ccePolicy` to an empty string.
After installing the [Azure `confcom` CLI extension](#policy-generation), run the following command to generate the security policy and include the `--debug-mode` option so that the policy allows users to shell into the container.
The `--debug-mode` option is only needed for testing purposes and should not be used in production, as it allows users to shell into the containers.
Note this should only be used for debugging and not recommended for production systems.
We are using this option since this is an example run.

```bash
az confcom acipolicygen -a aci-arm-template.json --debug-mode
```

This should automatically populate the [cce policy](aci-arm-template.json#L112) field of `aci-arm-template.json.`
If you run the tool on an ARM template with the `ccePolicy` field already populated, the tool will prompt you to overwrite the existing policy.

The security policy tool outputs the sha-256 hash of the policy upon completion.
Copy this output and replace the [hash-digest-of-the-security-policy](importkeyconfig.json#L22) string of the `importkeyconfig.json` file.

#### 8. Import Keys into mHSM/AKV

Once the key vault resource is ready and the `importkeyconfig.json` file is completely filled out, the user can import `RSA-HSM` or `oct-HSM` keys into it using the `importkey` tool placed under `<parent_repo_dir>/tools/importkey` as discussed in the tools' [readme file](https://github.com/microsoft/confidential-sidecar-containers/tree/main/tools/importkey).

Starting with release 2.6, we provide the importkey tool executables to remove the Golang dependency from the user.
Go to the [release page](https://github.com/microsoft/confidential-sidecar-containers/releases) and download the appropriate binary for your environment.
To import the key into AKV/mHSM, use the following command:

```bash
# using wsl
./importkey -c importkeyconfig.json -out=true

# using windows
importkey.exe -c importkeyconfig.json -out=true
```

Users have the option of adding salt to their key if they configured `RSA-HSM` key type on `importkeyconfig.json`.
Users can come up with their own salt but it must be a hex-encoded string.
If users choose to use salt, the salt must appear in both `importkeyconfig.json` and`encfs-sidecar-args.json`.
Upon successful import completion, you should see something similar to the following:

```text
[34 71 33 117 113 25 191 84 199 236 137 166 201 103 83 20 203 233 66 236 121 110 223 2 122 99 106 20 22 212 49 224]
https://<mhsm-name>.managedhsm.azure.net/keys/<key-vault-key-name>/8659****0cdff08
{"version":"0.2","anyOf":[{"authority":"<authority-url-name>","allOf":[{"claim":"x-ms-sevsnpvm-hostdata","equals":"aaa7***7cc09d"},{"claim":"x-ms-compliance-status","equals":"azure-compliant-uvm"},{"claim":"x-ms-sevsnpvm-is-debuggable","equals":"false"},{"claim":"x-ms-sevsnpvm-vmpl","equals":"0"}]}]}
```

In this case, use the following commands to verify the key has been successfully imported:

```bash
az account set --subscription "<SUBSCRIPTION>"
az keyvault key list --hsm-name <mHSM NAME> -o table
```

The main.go golang script generates a private rsa key or an oct key named `keyfile.bin` based on the key type configuration on `importkeyconfig.json`.
It then uploads the binary key file named `keyfile.bin` to the mHSM under the [key ID](importkeyconfig.json#L3) along with the key released policy from `importkeyconfig.json`.

#### 9. Encrypted Filesystem

After instantiating an [Azure Storage Container](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-create?toc=%2Fazure%2Fstorage%2Fblobs%2Ftoc.json&bc=%2Fazure%2Fstorage%2Fblobs%2Fbreadcrumb%2Ftoc.json&tabs=azure-portal) onto which the encrypted filesystem will be uploaded.
The roles *Reader* and *Storage Blob Reader* roles need to be assigned to the user-assigned managed identity.
Additionally, the role of *Storage Blob Contributor* needs to be assigned for a read-write filesystem.

Copy the `keyfile.bin` generated from last step to `examples/encfs/generatefs` folder.

The script `generatefs/generatefs.sh` does the following in order:

1. Encrypts the contents of the `generatefs/filesystem` directory with `keyfile.bin`
2. Creates an encrypted file system image named `encfs.img`.

You may need to adjust the [size of the image](generatefs.shL#26) in the script, as it isn't calculated automatically.

```text
[!] Generating keyfile...
1+0 records in
1+0 records out
32 bytes copied, 0.00142031 s, 22.5 kB/s
keyfile exists
Key in hex string format
[!] Creating encrypted image...
Key slot 0 created.
Command successful.
[!] Formatting as ext4...
mke2fs 1.45.5 (07-Jan-2020)
Creating filesystem with 12288 4k blocks and 12288 inodes

Allocating group tables: done
Writing inode tables: done
Creating journal (1024 blocks): done
Writing superblocks and filesystem accounting information: done

[!] Mounting...
[!] Copying contents to encrypted device...
lost+found  test.txt
[!] Closing device...
```

The user needs to upload the blob to the previously generated storage container by uploading to the Azure Portal, using [az storage blob upload](https://learn.microsoft.com/en-us/azure/storage/blobs/storage-quickstart-blobs-cli), or using [azcopy](https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azcopy-v10?toc=%2Fazure%2Fstorage%2Fblobs%2Ftoc.json&bc=%2Fazure%2Fstorage%2Fblobs%2Fbreadcrumb%2Ftoc.json).
When uploading the blob, the type must be specified as a "page blob" for a read-write filesystem.
However, block blobs are allowed for read-only filesystems.

```az storage blob upload --file generatefs/encfs.img --container-name <storage container name> --name <name of blob of the image generated> --account-name <storage account name> --type <page or block blob> --auth-mode login```

```azcopy copy --blob-type=PageBlob ./generatefs/encfs.img 'https://<storage-container-uri>.blob.core.windows.net/private-container/encfs.img```

The url of the uploaded blob needs to be copied into [`encfs-sidecar-args.json`](encfs-sidecar-args.json#L5) file.

At this point, the `encfs-sidecar-args.json` file should be completely filled out and the user needs to base64 encode the contents and copy it to [`EncfsSideCarArgs`](aci-arm-template.json#L36).

#### 10. Deployment

Go to Azure portal and click on `deploy a custom template`, then click `Build your own template in the editor`.
By this time, the `aci-arm-template.json` file should be completely filled out.
Copy and paste the ARM template into the field start a deployment.
Once the deployment completes, the user can shell into the applicaiton container and execute the following commands:

```bash
# ls /mnt/remote/share/
lost+found  test.txt

/ # cat /mnt/remote/share/test.txt
This is a file inside the filesystem.
```

Alternatively, the enabled command in test-encfs-container outputs the following log, which users are able to see under the Logs tab.

```text
This is a file inside the filesystem.
This is a file inside the filesystem.
```
