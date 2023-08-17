# Encrypted filesystem container example

## Table of Contents
- [Policy generation](#policy-generation)
- [Step by Step Example](#step-by-step-example)

### Policy generation
Deploying a confidential container group requires generating a security policy that restricts what containers can run within the container group. To generate security policies, install the Azure `confcom` CLI extension by following the instructions [here](https://github.com/Azure/azure-cli-extensions/tree/main/src/confcom/azext_confcom#microsoft-azure-cli-confcom-extension-examples).  

The ARM template can be used directly to generate a security policy. The following command generates a security policy and automatically injects it into the template. Make sure `--debug-mode` option is included so that the generated policy allows shelling into container to see the released key in this example. NOTE: the current image used in the ARM template is built upon commit id a82b530. 

```
az confcom acipolicygen -a aci-skr-arm-template.json --debug-mode
```

The ARM template file file includes two entries: (i) encrypted filesystem sidecar container which whitelists the /encfs.sh as entry point command and the environment variable *EncfsSideCarArgs* used by the script, and (ii) an application container which whitelists a while loop command as entry point command.

### Step by Step Example 

Here is an example of running the encfs sidecar on confidential ACI. The MAA endpoint is the value of env var [Authority Endpoint](encfs-sidecar-args.json#L12). 
The managed HSM instance endpoint corresponds to [AKV Endpoint](encfs-sidecar-args.json#L15). We will also define and import a key into the managed HSM as shown in [`importkeyconfig.json`](importkeyconfig.json#L2)


#### 1. Obtain an Attestation Endpoint

If you don't already have a valid attestation endpoint, create a [Microsoft Azure Attestation](https://learn.microsoft.com/en-us/azure/attestation/overview) endpoint to author the attestation token and run the following command to get the endpoint value:

```
az attestation show --name "<ATTESTATION PROVIDER NAME>" --resource-group "<RESOURCE GROUP>"
```

Copy the AttestURI endpoint value (sans https://) to the [Attestation Authority endpoint](importkeyconfig.json#L6) in `importkeyconfig.json` and to [Attestation Authority endpoint](encfs-sidecar-args.json#L12) in `encfs-sidecar-args.json`.


#### 2. Generate User Managed Identity 

The user needs to instantiate an Azure Key Vault resource that supports storing keys in an HSM: a [Premium vault](https://learn.microsoft.com/en-us/azure/key-vault/general/overview) or an [MHSM resource](https://docs.microsoft.com/en-us/azure/key-vault/managed-hsm/overview).

After setting up an Azure Key Vault resource, generate a user-assigned managed identity that will be attached to the container group so that the containers have the correct access permissions to Azure services and resources. The managed identity needs *Key Vault Crypto Officer* and *Key Vault Crypto User* roles if using AKV key vault or *Managed HSM Crypto Officer* and *Managed HSM Crypto User* roles for /keys if using AKV managed HSM. More information about creating identities can be found [here.](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/)

If you already have a user-assigned managed identity with the appropriate access permissions, run the following command to list the managed identities for a resource group:

```
az identity list -g <RESOURCE GROUP>
```

Or you can use the following command if you know the name of the managed identity and the resource group:

```
az identity show -g <RESOURCE GROUP> -n <MANAGED IDENTITY NAME>
```

Replace [managed-identity-with-right-permissions-to-key-vault](aci-arm-template.json#L22) of `aci-arm-template.json` with the identity ID.


#### 3. Populate Image Registry Credentials

Update the [image registry credentials](aci-arm-template.json?plain=1#L87) on the ARM template in order to access a private container registry. The credential could be either a managed identity or username/password. This section is not needed for public images. 


#### 4. Obtain the AAD token

The AAD token with permission to AKV/mHSM can be obtained with the following command:

```
az account get-access-token --resource https://managedhsm.azure.net
```

Replace [AAD token](importkeyconfig.json#L11) in `importkeyconfig.json` with the output accessToken.
Replace [ENCFS AKV endpoint](encfs-sidecar-args.json#L15) in `enfcs-sidecar-args.json` with the mhsm endpoint.

#### 5. Fill in Key Information

After setting up an [Azure Key Vault resource](#import-key), fill in the `importkeyconfig.json` file with the name of the key to be created and imported into the key vault [Key name](importkeyconfig.json#L3). Additionally, fill in `encfs-sidecar-args.json` with the name of the key to be created and imported into the key vault [Key name](encfs-sidecar-args.json#L9).

Additionally, fill in the optional [key derivation](importkeyconfig.json#L14) for RSA keys and [Key type: `RSA-HSM` or `oct-HSM`](importkeyconfig.json#L4) fields or remove these fields from the `importkeyconfig.json` file. Fill in [key derivation](encfs-sidecar-args.json#L18) and [Key type: `RSA-HSM` or `oct-HSM`](encfs-sidecar-args.json#L10) in `encfs-sidecar-args.json` as well.


#### 6. Encrypted Filesystem
The user needs to instantiate an [Azure Storage Container](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-create?toc=%2Fazure%2Fstorage%2Fblobs%2Ftoc.json&bc=%2Fazure%2Fstorage%2Fblobs%2Fbreadcrumb%2Ftoc.json&tabs=azure-portal) onto which the encrypted filesystem will be uploaded. The roles *Reader* and *Storage Blob Reader* roles need to be assigned to the user-assigned managed identity. Additionally, the role of *Storage Blob Contributor* needs to be assigned for a read-write filesystem.

The script `generatefs/generatefs.sh` creates `encfs.img` with the contents of the `generatefs/filesystem` directory. You may need to adjust the size of the image in the script, as it isn't calculated automatically. 

The script expects a symmetric key stored in binary format `keyfile.bin` previously created during key import phase. If not passed, the script will generate a new one and the user will need to follow the import key instructions on the new key.

```
[!] Generating keyfile...
1+0 records in
1+0 records out
32 bytes copied, 0.00142031 s, 22.5 kB/s
keyfile exists
Key in hex string format
b'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
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

The user needs to upload the blob to the previously generated storage container by uploading to the Azure Portal, using [az storage blob upload] (https://learn.microsoft.com/en-us/azure/storage/blobs/storage-quickstart-blobs-cli), or using [azcopy] (https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azcopy-v10?toc=%2Fazure%2Fstorage%2Fblobs%2Ftoc.json&bc=%2Fazure%2Fstorage%2Fblobs%2Fbreadcrumb%2Ftoc.json).

```az storage blob upload --file generatefs/encfs.img --container-name <storage container name> --name <name of block blob of the image generated> --account-name <storage account name> --sas-token '<SAS token starting with sp within single quotations>'```

```azcopy copy --blob-type=PageBlob ./generatefs/encfs.img 'https://<storage-container-uri>.blob.core.windows.net/private-container/encfs.img```

The url of the uploaded blob needs to be copied into [`encfs-sidecar-args.json`](encfs-sidecar-args.json#L5) file. 

At this point, the `encfs-sidecar-args.json` file should be completely filled out and the user needs to base64 encode the contents and copy it to [`EncfsSideCarArgs`](aci-arm-template.json#L36).


#### 7. Generate Security Policy

At this point, the `aci-arm-template.json` file should be filled out except for the `ccepolicy` field. After installing the [Azure `confcom` CLI extension](#policy-generation), run the following command to generate the security policy and include the `--debug-mode` option so that the policy allows users to shell into the container. The --debug-mode option is only needed for testing purposes and should not be used in production, as it allows users to shell into the containers.

```
az confcom acipolicygen -a aci-arm-template.json --debug-mode
```

This should  automatically populate the [cce policy](aci-arm-template.json#L106) field of `aci-arm-template.json.` If you run the tool on an arm template with the cce policy field already populated, the tool will prompt you to overwrite the existing policy.

The security policy tool outputs the sha-256 hash of the policy upon completion. Copy this output and replace the [hash-digest-of-the-security-policy](importkeyconfig.json#L22) string of the `importkeyconfig.json` file.


#### 8. Import Keys into mHSM/AKV

Once the key vault resource is ready and the `importkeyconfig.json` file is completely filled out, the user can import `RSA-HSM` or `oct-HSM` keys into it using the `importkey` tool placed under `<parent_repo_dir>/tools/importkey` as discussed in the tools' [readme file](https://github.com/microsoft/confidential-sidecar-containers/tree/main/tools/importkey).

A fake encryption key is used in the command below to see the key get released. To import the key into AKV/mHSM, use the following command:

```
go run /tools/importkey/main.go -c importkeyconfig.json -kh encryptionKey
```

Upon successful import completion, you should see something similar to the following: 

```
[34 71 33 117 113 25 191 84 199 236 137 166 201 103 83 20 203 233 66 236 121 110 223 2 122 99 106 20 22 212 49 224]
https://accmhsm.managedhsm.azure.net/keys/doc-sample-key-release/8659****0cdff08
{"version":"0.2","anyOf":[{"authority":"https://sharedeus2.eus2.test.attest.azure.net","allOf":[{"claim":"x-ms-sevsnpvm-hostdata","equals":"aaa7***7cc09d"},{"claim":"x-ms-compliance-status","equals":"azure-compliant-uvm"},{"claim":"x-ms-sevsnpvm-is-debuggable","equals":"false"}]}]}
```

In this case, use the following commands to verify the key has been successfully imported: 

```
az account set --subscription "<SUBSCRIPTION>"
az keyvault key list --hsm-name <MHSM NAME> -o table
```


#### 9. Deployment

Go to Azure portal and click on `deploy a custom template`, then click `Build your own template in the editor`. By this time, the `aci-arm-template.json` file should be completely filled out. Copy and paste the ARM template into the field start a deployment. Once the deployment completes, the user can shell into the applicaiton container and execute the following commands:

```
# ls /mnt/remote/share/
lost+found  test.txt

/ # cat /mnt/remote/share/test.txt 
This is a file inside the filesystem.
```

Alternatively, the whitelisted command in test-encfs-container outputs the following log, which users are able to see under the Logs tab.
```
This is a file inside the filesystem.
This is a file inside the filesystem.

```