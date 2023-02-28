# Encrypted filesystem container example

## Preparation

### Managed identity
The user needs to generate a user-assigned managed idenity which will be attached to the container group so that the containers can have the right access permissions to Azure services and resources. More information about creating identities can be found [here.](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/)

### Security policy generation
Deploying a confidential container group requires generating a security policy that restricts what containers can run within the container group. There is an az tool available for generating policies. See [here](https://github.com/Azure/azure-cli-extensions/tree/main/src/confcom/azext_confcom#microsoft-azure-cli-confcom-extension-examples) for installing Azure `confcom` CLI extension.  

The ARM template can be used directly to generate a security policy. The following command generates a security policy and automatically injects it into the template. 

```az confcom acipolicygen -a aci-arm-template.json```

The ARM template file file includes two entries: (i) encrypted filesystem sidecar container which whitelists the /encfs.sh as entry point command and the environment variable *EncfsSideCarArgs* used by the script, and (ii) an application container which whitelists a while loop command as entry point command. NOTE: the current image used in the ARM template is built upon commit id a82b530. 

### Import encryption key
The user needs to instantiate an Azure Key Vault resource that supports storing keys in an HSM: a [Premium vault](https://learn.microsoft.com/en-us/azure/key-vault/general/overview) or an [MHSM resource](https://docs.microsoft.com/en-us/azure/key-vault/managed-hsm/overview). For the former, the user needs to assign 
the *Key Vault Crypto Officer* and *Key Vault Crypto User* roles to the user-assigned managed identity and for the latter, the user needs to assign *Managed HSM Crypto Officer* and *Managed HSM Crypto User* roles for /keys to the user-assigned managed identity.

Once the key vault resource is ready, the user can import `RSA-HSM` or `oct-HSM` keys into it using the `importkey` tool placed under `<parent_repo_dir>/tools/importkey` after updating the `importkeyconfig.json` with the required information as discussed in the tools' readme file. For instance, the hostdata claim value needs to be set to the hash digest of the security policy, which can be obtained by executing the following command:

`go run <parent_dir>/tools/securitypolicydigest/main.go -p <base64-std-encoded-string-of-security-policy>`

And the AAD token with permission to AKV/mHSM can be obtained with the following command:

`az account get-access-token --resource https://managedhsm.azure.net`

Once the `importkeyconfig.json` is updated, execute the following command:

`cd <parent_dir>/tools/importkey`

`go run main.go -c <parent_dir>/examples/encfs/importkeyconfig.json -kh <hexstring encoding oct-HSM key> -out`

`go run main.go -c <parent_dir>/examples/encfs/importkeyconfig.json -kp private-key.pem -out`

`go run main.go -c <parent_dir>/examples/encfs/importkeyconfig.json -out`

For `RSA-HSM` keys, the `importkey` (if prompted using the `-out` flag) derives an octet key from the RSA private key. Note that it is safe
to use the private RSA key as entropy for a symmetric key as logn as the RSA key pair is not used for any other cryptographic operation.

### Encrypted filesystem
The user needs to instantiate an [Azure storage container](https://docs.microsoft.com/en-us/azure/storage/common/storage-use-azcopy-blobs-upload) onto which the encrypted filesystem will be uploaded. The roles *Reader* and *Storage Blob Reader* roles need to be assigned to the user-assigned managed identity.

The script `generatefs/generatefs.sh` creates `encfs.img` with the contents of the `generatefs/filesystem` directory. You may need to adjust the size of the image in the script, as it isn't calculated automatically. 

The script expects a symmetric key stored in binary format `keyfile.bin` previously created during key import phase. If not passed, the script will generate a new one and the user will need to follow the import key instructions.

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

The user needs to upload the blob to the previously generated storage container 

```azcopy copy --blob-type=PageBlob ./generatefs/encfs.img 'https://<storage-container-uri>.blob.core.windows.net/private-container/encfs.img?<SAS_token_to_container_with_write_create_read_permissions>```

## Testing
In our confidential container group example, we will deploy the encrypted filesystem sidecar along with a simple container that runs indefinitely. The simple container will have access to the remote filesystem mounted by the sidecar container.

### Deployment
The `aci-arm-template.json` provides an ACI ARM template which can be parametrized using the security policy obtained above, the registry name (and credentials if private), the user-assigned managed identity, and the encrypted filesystem sidecar's *EncfsSideCarArgs* set to the base64-std-encoded-string of the sidecar's runtime attribute specified in the `encfs-sidecar-args.json` 

Once the deployment completes, the user can shell into the applicaiton container and execute the following commands:

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
