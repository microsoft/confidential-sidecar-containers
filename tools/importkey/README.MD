# importkey

Takes a path to a JSON configuration file and imports a key to Azure Key Vault resource, supporting both AKV Premium and Managed HSM.
The tool will succeed only if the Azure user has the right access permissions to the Azure Key Vault endpoint.
Upon successful import key operation, it outputs the secret and the keypath (aka key identifier).

> `importkey` exists as a tool to make it easier to import keys to a key vault.
It is not intended to be used by "end users" but could be used as a basis for such a tool.

When importing a key to the key vault, a release policy is coupled with the key.
The tool follows the schema of AKV SKR API to add a series of claims that need to be satisfied.
The authority (MAA endpoint) is also included in the policy so that the vault is authorized to release secrets upon receiving valid MAA tokens generated by the MAA endpoint.

## Example import key configuration file

```json
{
    "key":{
        "kid": "AttestationContainer2",
        "kty": "RSA-HSM",
        "authority": {
            "endpoint": "sharedneu.neu.attest.azure.net"
        },
        "akv": {
            "endpoint": "myhsm.managedhsm.azure.net",
            "api_version": "api-version=7.4",
            "bearer_token": ""
        }
    },
    "key_derivation":{
        "salt": "92a631483ca875aad7e2477da755d58cac3876b77d10bcdd7b33bfa11e7d8b8e",
        "label": "Model Encryption Key"
    },
    "claims":[
        [
            {
                "claim":  "x-ms-sevsnpvm-hostdata",
                "equals": "99e1abd344fc0989288c44fde8de3b2a248b1b95814df8955d0c305a7db46680"
            },
            {
                "claim": "x-ms-compliance-status",
                "equals": "azure-compliant-uvm"
            },
            {
                "claim": "x-ms-sevsnpvm-is-debuggable",
                "equals": "false"
            },
            {
                "claim": "x-ms-sevsnpvm-vmpl",
                "equals": "0"
            }
        ]
    ]
}
```

The tool currently supports two types of keys specified in the `kty` attribute of the configuration: `RSA-HSM` and `oct-HSM` (default operation mode).

The tool randomly samples an RSA or an octet key. 

Alternatively, the user may specify a path to the private RSA key in `ASN.1 DER` wrapped in `PKCS8` format or the octet key to import (oct-HSM) in hexstring format.

## CLI Options

Required:

- `-c` -  configuration file to process

Optional:

- `-kh` - Path for octet key or contents of octet key

- `-kp` - Path for RSA key in `ASN.1 DER` wrapped in `PKCS8` format.

- `-a` - Flag to indicate whether running inside Azure (`default = false`)

- `-out` - Flag to indicate whether outputting a binary file containing the oct key.
    For RSA keys, the oct key is derived from the RSA's secret exponent.

The key derivation information may be passed via the `key_derivation` attribute (salt passed as a hexstring and label passed as a string).

The tool can work outside an Azure VM by obtaining the token from the `akv.BearerToken` field in the configuration file.

The field can be updated using a token retrieved using the commands:

```shell
az login
az account get-access-token --resource https://managedhsm.azure.net
```

The tool can work inside an Azure VM assuming the VM has been assigned a managed identity that has the right permissions to access the AKV endpoint.
