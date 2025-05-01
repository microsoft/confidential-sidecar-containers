The ```remotefs``` tool takes base64 standard encoded string of information (see below) about all remote encrypted filesystems that need to be mounted.
The URL can be private (accessed using token credentials obtained for a user-defined identity) or public (accessed using anonymous credentials for public containers or SAS token for private containers).
The SKR information specifies the key identifier, the key type, the AKV endpoint in which the key is stored, and the authority endpoint which can authorize the AKV for releasing the key.
Key release is authorized assuming the release policy is satisfied with claims presented in the authority's token.
If the key provided is RSA-HSM, the key_derivation object needs to be specified so that the tool can derive a symmetric key using the RSA key material and the key_derivation salt and label.
For testing purposes, it is possible to pass the raw hexstring key as opposed to SKR information.
Additionally, a read_write flag must be specified to determine if the filesystem is read-write, otherwise the filesystem defaults to read-only.

```
{
    "azure_filesystems":[
        {
            "mount_point":"/remotemounts/share1",
            "azure_url":"https://samplename.blob.core.windows.net/public-container/image-encrypted-1.img",
            "azure_url_private": true,
            "read_write": false,   
            "key": {
                 "kid": "EncryptedFilesystemsContainer",
                 "kty": "RSA-HSM",
                 "authority": {
                     "endpoint": "sharedneu.neu.attest.azure.net"
                 },
                 "akv": { 
                     "endpoint": "avaultname.vault.azure.net"
                 }
            },
            "key_derivation":{
                "salt": "92a631483ca875aad7e2477da755d58cac3876b77d10bcdd7b33bfa11e7d8b8e",
                "label": "Encryption Key"
            }           
        },
        {
            "mount_point":"/remotemounts/share2",
            "azure_url":"https://myname.blob.core.windows.net/private-container/image-encrypted-2.img",
            "azure_url_private": true,
            "key": {
                 "kid": "EncryptedFilesystemsContainer",
                 "authority": {
                     "endpoint": "sharedneu.neu.attest.azure.net"
                 },
                 "akv": { 
                     "endpoint": "amanagedhsmname.managedhsm.azure.net"
                 }
            }         
        }
    ]
}
```

The tool does the following for each filesystem (any failure will cause the program to exit):

- It invokes ```azmount``` to expose the encrypted file specified in ``azure_url`` as
  a local file.
  This file is read-only, unless a read-write filesystem is specified.
  Public containers can be read, but they can't be written unless the user is authenticated. 

  Also, the reason why this is a separate tool is that this tool uses FUSE to expose the remote file as a local file.
  This turns the userland process into a server of Kernel requests (such as read or write), and it is needed to have a different process per FUSE filesystem.

  Because this tool is running on a different process, remotefs has to wait until the expected file is available.
  This has a timeout of 10 seconds.

- The keyfile is obtained from either SKR or the hardcoded key in the tool.
  If the key material released using SKR is an `RSA-HSM`, the tool uses the key derivation information to derive a symmetric/octet key.

- The encrypted file and the key file are passed to cryptsetup so that the encrypted file is exposed as an unencrypted block device under ``/dev/mapper/desired-name``.

  Then, this block device is mounted to an intermediate location.
  The process of creating a folder and mounting a filesystem there isn't atomic, so this can't be done in the final destination.

- Finally, a symlink is created in the final location, which points to the intermediate location.
  This step is atomic, so the expected final path won't appear until the filesystem is available inside of it.