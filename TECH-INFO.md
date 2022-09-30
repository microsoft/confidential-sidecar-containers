# azmount and remotefs
The encrypted filesystem sidecar container relies on two tools azmount and remotefs. 

## remotefs
This tool takes an argument such as this:

```
{
    "azure_filesystems":[
        {
            "mount_point":"/remotemounts/share1",
            "azure_url":"https://samplename.blob.core.windows.net/public-container/image-encrypted-1.img",
            "azure_url_private": false,
            "key": {
                 "kid": "EncryptedFilesystemsContainer",
                 "authority": {
                     "endpoint": "sharedneu.neu.attest.azure.net"
                 },
                 "mhsm": { 
                     "endpoint": "anhsmname.managedhsm.azure.net"
                 }
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
                 "mhsm": { 
                     "endpoint": "anotherhsmname.managedhsm.azure.net"
                 }
            }              
        }
    ],
    "azure_info": {
        "certcache": {
            "endpoint": "americas.test.acccache.azure.net",
            "tee_type": "SevSnpVM",
            "api_version": "api-version=2020-10-15-preview"
        } 
    }
}
```

It must be provided as a base64-encoded string.

The tool takes this information and mounts every filesystem specified in each
URL in the corresponding mountpoint. The URL can be private (which will be accessed
using token credentials obtained for a user-defined identity) or public (which will
be accessed using anonymous credentials.)

The SKR information need to specify the key identifier, the MHSM endpoint in which the 
key is stored, and the authority endpoint which can authorize the MHSM for releasing 
the key assuming the release policy is satisfied with claims presented in the authority's 
token. For SKR, we also need to include the certcache endpoint from which the SKR library 
can retrieve a certificate chain for the attestation's signing key pair. For testing
purposes, it is possible to pass the raw hexstring key as opposed to SKR information.

In order to get this to work, the tool does the following for each filesystem
(any failure will cause the program to exit):

- It invokes azmount to expose the encrypted file specified in ``azure_url`` as
  a local file. This file is read-only. Public containers can be read, but they
  can't be written unless the user is authenticated. 

  Also, the reason why this is a sepparate tool is that this tool uses FUSE to
  expose the remote file as a local file. This turns the userland process into a
  server of Kernel requests (such as read or write), and it is needed to have a
  different process per FUSE filesystem.

  Because this tool is running on a different process, remotefs has to wait
  until the expected file is available. This has a timeout of 10 seconds.

- The keyfile is obtained from either SKR or the hardcoded key in the tool.

- The encrypted file and the key file are passed to cryptsetup so that the
  encrypted file is exposed as an unencrypted block device under
  ``/dev/mapper/desired-name``.

  Then, this block device is mounted to an intermediate location. The process of
  creating a folder and mounting a filesystem there isn't atomic, so this can't
  be done in the final destination.

- Finally, a symlink is created in the final location, which points to the
  intermediate location. This step is atomic, so the expected final path won't
  appear until the filesystem is available inside of it.

## azmount
This tool exposes a file located in Azure Blob Storage as a local file. For
example, the tool can be used like this:

```
mkdir /tmp/test
azmount -url https://samplename.blob.core.windows.net/public-container/image-encrypted.img -mountpoint /tmp/test
```

This will result in a file: ``/tmp/test/data``, which contains the contents of
the file from Azure Blob Storage.

Alternatively, it can also mount a local file for testing purposes:

```
mkdir /tmp/test
azmount -localpath /home/example/myfile -mountpoint /tmp/test
```

``azmount`` will keep running until the user does:

```
unmount /tmp/test
```

The way the program works is:

- It uses FUSE to expose the remote file as a local file.

- Whenever the program gets a read request from the kernel, it checks if that
  part of the file is in the local cache of blocks. If it isn't, it fetches it
  from Azure Blob Storage and saves it to the cache.

  It is needed to keep a local cache because the kernel tends to do lots of
  small reads of a few KB in size rather than big reads, which has a big
  performance cost.

Other command line options are:

- ``loglevel``: Specify the log level.
- ``logfile``: Specify a path to use as log file instead of directing the log
  output to stdout.
- ``blocksize``: Size of a cache block in KiB.
- ``numblocks``: Number of cache blocks to keep.

# skr
We also provide a stand-alone tool for attestation and secure key release. This tool instantiates a web server which exposes a REST API so that other containers can retrieve a hardware attestation report via the POST method `attest/raw` or an MAA token via the POST method `attest/maa`, and release a key via the POST method `key/release`. The server is configured with a certificate cache endpoint during startup, and can be reached at http://localhost:8080. 

The tool can be executed using the script https://github.com/Microsoft/confidential-sidecar-containers/blob/skr.sh and optionally the certificate cache endpoint information as an attribute to it or as an environment variable `SkrSidecarArgs`. If the script is executed without any certificate cache endpoint information, only  the `attest/raw` POST method is available.

The information for the cerificate cache endpoint is passed as a base64-encoded string and has the following schema

```json
{
   "certcache": {
      "endpoint": "americas.test.acccache.azure.net",
      "tee_type": "SevSnpVM",
      "api_version": "api-version=2020-10-15-preview"
   }
}
```


## API
The `status` GET method returns the status of the server. The response carries a `StatusOK` header and a payload of the following format:

```json
{
    "message": "STATUS OK"
}

{
    "message": "STATUS NOT OK"
}
```

The `attest/raw` POST method expects a JSON of the following format:

```json
{	    
    "runtime_data": "<Base64-encoded blob that will be presented as ReportData in hardware attestation report>"    
}
```

Upon success, the `attest/raw` POST method reponse carries a `StatusOK` header and a payload of the following format:

```json
{
    "report": "<hardware attestation report in hexstring format>"
}
```

The `attest/maa` POST method expects a JSON of the following format:

```json
{	
    "maa_endpoint": "<maa endpoint>",
    "runtime_data": "<Base64-encoded blob that will be presented as runtime claim in maa token>"    
}
```

Upon success, the `attest/maa` POST method reponse carries a `StatusOK` header and a payload of the following format:

```json
{
    "token": "<MAA token formatted in JSON Web Token format>"
}
```

Upon error, the `attest/raw` and `attest/maa` POST methods response carries a `BadRequest` or `StatusForbidden` header and a payload of the following format:

```json
{
    "error": "<error message>"
}
```

The `key/release` POST method expects a JSON of the following format:

```json
{	
    "maa_endpoint": "<maa endpoint>",
    "mhsm_endpoint": "<mhsm endpoint>",
    "kid": "<key identifier>",
    "access_token": "optional aad token if the command will run in a resource without proper managed identity assigned"
}
```

Upon success, the `key/release` POST method reponse carries a `StatusOK` header and a payload of the following format:

```json
{
    "key": "<hexstring representation of the key>"
}
```

Upon error, the `key/release` POST method response carries a `StatusForbidden` header and a payload of the following format:

```json
{
    "error": "<error message>"
}
```
