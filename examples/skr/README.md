# Attestation and Secure Key Release Sidecar Example

## Table of Contents
- [Policy generation](#policy-generation)
- [Step by Step Example](#step-by-step-example)

In our confidential container group example, we will deploy the skr sidecar along with a set of test containers that exercise and test the REST API.
- **skr sidecar.** The sidecar’s entry point is /skr.sh which uses the SkrSideCarArgs environment variable to pass the certificate cache endpoint information.
- **attest/raw test.** The sidecar’s entry point is /tests/skr/attest_client.sh which uses the AttestClientRuntimeData environment variable to pass a blob whose sha-256 digest will be encoded in the raw attestation report as report_data.
- **attest/maa test.** The sidecar’s entry point is /tests/skr/attest_client.sh which uses two environment variables: (i) AttestClientMAAEndpoint passes the Microsoft Azure Attestation endpoint which will author the attestation token, (ii) AttestClientRuntimeData passes a blob whose sha-256 digest will be encoded in the attestation token as runtime claim.
- **key/release test.** The sidecar’s entry point is /tests/skr/skr_client.sh which uses the three environment variables: (i) SkrClientKID passes the key identifier of the key to be released from the key vault, (ii) SkrClientAKVEndpoint passes the key vault endpoint from which the key will be released, and (iii) SkrClientMAAEndpoint passes the Microsoft Azure Attestation endpoint shall author the attestation token required for releasing the secret. The MAA endpoint shall be the same as the one specified in the SKR policy during the key import to the key vault.


### Policy generation
Deploying a confidential container group requires generating a security policy that restricts what containers can run within the container group. To generate security policies, install the Azure `confcom` CLI extension by following the instructions [here](https://github.com/Azure/azure-cli-extensions/tree/main/src/confcom/azext_confcom#microsoft-azure-cli-confcom-extension-examples).  

The ARM template can be used directly to generate a security policy. The following command generates a security policy and automatically injects it into the template. Make sure `--debug-mode` option is included so that the generated policy allows shelling into container to see the released key in this example. NOTE: the current image used in the ARM template is built upon commit id a82b530. 

```
az confcom acipolicygen -a aci-skr-arm-template.json --debug-mode
```

The ARM template file includes three entries: (i) skr sidecar container which whitelists the /skr.sh as entry point command and the environment variable SkrSideCarArgs used by the script, (ii) attest_client container which whitelists the /tests/skr/attest_client.sh as entry point command and a set of environment variables used by the script and whose names begin with AttestClient, and  (iii) skr_client container which whitelists the /tests/skr_client.sh as entry point command and a set of environment variables used by the script and whose names begin with SkrClient. 
Please note that:
- The skr sidecar must be allowed to execute as elevated because it needs access to the PSP which is mounted as a device at /dev/sev. 
- The policy includes one entry for both attestation tests, as both tests use the same entry point and a superset of environment variables whitelisted by the AttestClient regular expression.


### Step by Step Example 

Here is an example of running skr sidecar on confidential ACI. The MAA endpoint is the value of env var [`SkrClientMAAEndpoint`](aci-arm-template.json?plain=1#L55). 
The managed HSM instance endpoint corresponds to [`SkrClientAKVEndpoint`](aci-arm-template.json?plain=1#L59). We will also import a key into managed HSM under the name [`doc-sample-key-release`](aci-arm-template.json?plain=1#L64)


#### 1. Obtain an Attestation Endpoint

If you don't already have a valid attestation endpoint, create a [Microsoft Azure Attestation](https://learn.microsoft.com/en-us/azure/attestation/overview) endpoint to author the attestation token and run the following command to get the endpoint value:

```
az attestation show --name "<ATTESTATION PROVIDER NAME>" --resource-group "<RESOURCE GROUP>"
```

Copy the AttestURI endpoint value (sans https://) to the [Attestation Authority endpoint](importkeyconfig.json#L6) in `importkeyconfig.json` and to [SkrClientMAAEndpoint](aci-arm-template.json#L56) and [AttestClientMAAEndpoint](aci-arm-template.json#L106) in `aci-arm-template.json`.


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

Replace [managed-identity-with-right-permissions-to-key-vault](aci-arm-template.json#:~:text=%22%3Cmanaged%2Didentity%2Dwith%2Dright%2Dpermissions%2Dto%2Dkey%2Dvault%3E%22) of `aci-arm-template.json` with the identity ID.


#### 3. Populate Image Registry Credentials

Update the [image registry credentials](aci-arm-template.json?plain=1#L123) on the ARM template in order to access a private container registry. The credential could be either a managed identity or username/password. This section is not needed for public images. 


#### 4. Obtain the AAD token

The AAD token with permission to AKV/mHSM can be obtained with the following command:

```
az account get-access-token --resource https://managedhsm.azure.net
```

Replace [AAD token](importkeyconfig.json#L11) in `importkeyconfig.json` and [SkrClientAKVEndpoint](aci-arm-template.json#L60) in `aci-arm-template.json` with the output accessToken.


#### 5. Fill in Key Information

After setting up an [Azure Key Vault resource](#import-key), fill in the `importkeyconfig.json` file with the name of the key to be created and imported into the key vault [Key name](importkeyconfig.json#L3).

Additionally, fill in the optional [key derivation](importkeyconfig.json#L14) for RSA keys and [Key type: `RSA-HSM` or `oct-HSM`](importkeyconfig.json#L4) fields or remove these fields from the `importkeyconfig.json` file.

Copy the key name into [SkrClientKID](aci-arm-template.json#L64) in the `aci-arm-template.json`.


#### 6. Generate Security Policy

At this point, the `aci-arm-template.json` file should be filled out except for the `ccepolicy` field. After installing the [Azure `confcom` CLI extension](#policy-generation), run the following command to generate the security policy and include the `--debug-mode` option so that the policy allows users to shell into the container. 

```
az confcom acipolicygen -a aci-arm-template.json --debug-mode
```

This should prompt you to automatically populate the [cce policy](aci-arm-template.json#L142) field of `aci-arm-template.json.`


#### 7. Generate Security Policy Hash 

Use the tools in this repository to obtain the security hash of the generated policy and the key to be imported into AKV/mHSM. Start by cloning the repository locally:

```
git clone git@github.com:microsoft/confidential-sidecar-containers.git
```

Copy the value of the generated `ccePolicy` from the ARM template and at the root of the cloned repo, obtain the sha256 hash of the security policy by running: 

```
go run tools/securitypolicydigest/main.go -p ccePolicyValue
```

At the end of the command output, you should see something similar to the following: 

    inittimeData sha-256 digest **aaa4e****cc09d**

Copy the digest and replace the [hash-digest-of-the-security-policy](importkeyconfig.json#L22) string of the `importkeyconfig.json` file.


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
{"version":"1.0.0","anyOf":[{"authority":"https://sharedeus2.eus2.test.attest.azure.net","allOf":[{"claim":"x-ms-sevsnpvm-hostdata","equals":"aaa7***7cc09d"},{"claim":"x-ms-compliance-status","equals":"azure-compliant-uvm"},{"claim":"x-ms-sevsnpvm-is-debuggable","equals":"false"}]}]}
```

In this case, use the following commands to verify the key has been successfully imported: 

```
az account set --subscription "<SUBSCRIPTION>"
az keyvault key list --hsm-name <MHSM NAME> -o table
```

#### 9. Deployment

Go to Azure portal and click on `deploy a custom template`, then click `Build your own template in the editor`. By this time, the `aci-arm-template.json` file should be completely filled out. Copy and paste the ARM template into the field start a deployment. Once deployment is done, to verify the key has been successful released, shell into the `skr-sidecar-container` container and see the log.txt and you should see the following log message: 

```
level=debug msg=Releasing key blob: {doc-sample-key-release}
```

Alternatively, you can shell into the container `test-skr-client-hsm-skr` and the released key is in keyrelease.out. 
