# importkey

Takes a configuration to a JSON file and imports a random octet key to Azure Key Vault Managed HSM. The tool will succeed only if the Azure user has the right access permissions to the MHSM endpoint. Upon successful import key operation, it outputs the secret and the keypath (aka key identifier).

`importkey` exists as a tool to make it easier to import keys to a managed HSM. It is not intended to be used by "end users" but could be used as a basis for such a tool. 

When importing a key to the MHSM, a release policy is coupled with the key. The tool follows the schema of AKV MHSM SKR to add a series of claims that need to be satisfied. The authority (MAA endpoint) is also included in the policy so that the MHSM is authorized to release secrets upon receiving valid MAA tokens generated by the MAA endpoint.

## Example import key configuration file

```json
{
    "key":{
        "kid": "AttestationContainer2",
        "authority": {
            "endpoint": "sharedneu.neu.attest.azure.net"
        },
        "mhsm": {
            "endpoint": "svolos-myhsm.managedhsm.azure.net",    
            "api_version": "api-version=7.3-preview",
            "bearer_token": ""
        }
    },
    "claims":[
        {
            "claim":  "x-ms-sevsnpvm-hostdata",
            "equals": "99e1abd344fc0989288c44fde8de3b2a248b1b95814df8955d0c305a7db46680"
        }            
    ]
}
```

## CLI Options

- -c

    JSON configuration file to process (required)

- -kh

    Key hexstring for key to import (optional)

    For example, 2de649d47611ee8aaf2678aec4be58a0760233fa288c57243133d5fd0b16c7d2

- -a 

    Flag to indicate whether running inside Azure (optional, default = false)

The tool can work outside an Azure VM by obtaining the token from the mhsm.BearerToken field in the configuration file. The field can be updated using a token retrieved using the command

`az login`

`az account get-access-token --resource https://managedhsm.azure.net`

The tool can work inside an Azure VM assuming the VM has been assigned a managed identity that has the right permissions to access the MHSM endpoint. 