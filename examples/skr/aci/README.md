# Attestation and Secure Key Release Sidecar ACI Example

## 🔖 Table of Contents

- [Attestation and Secure Key Release Sidecar ACI Example](#attestation-and-secure-key-release-sidecar-aci-example)
  - [🔖 Table of Contents](#-table-of-contents)
  - [🌐 Overview](#-overview)
  - [🧰 Policy generation](#-policy-generation)
    - [Option 1 - ARM Template](#option-1---arm-template)
    - [Option 2 - Image-attached fragments](#option-2---image-attached-fragments)
  - [🚀 Quickstart -  Running SKR Sidecar on Confidential ACI](#-quickstart----running-skr-sidecar-on-confidential-aci)
    - [🔗 1. Obtain an Attestation Endpoint](#-1-obtain-an-attestation-endpoint)
    - [🔐 2. Azure Key Vault (AKV) and User Managed Identity](#-2-azure-key-vault-akv-and-user-managed-identity)
      - [Azure Key Vault CLI Command Summary](#azure-key-vault-cli-command-summary)
      - [2.1 Create an AKV](#21-create-an-akv)
      - [2.2 Generate a User Managed Identity](#22-generate-a-user-managed-identity)
      - [2.3 Check User Managed Identity](#23-check-user-managed-identity)
    - [🪪 3. Populate Image Registry Credentials](#-3-populate-image-registry-credentials)
    - [🪙 4. Obtain the AAD token](#-4-obtain-the-aad-token)
    - [📝 5. Fill in Key Information](#-5-fill-in-key-information)
    - [📄 6. Generate Security Policy](#-6-generate-security-policy)
    - [📤 7. Import Keys into mHSM/AKV](#-7-import-keys-into-mhsmakv)
    - [📦 8. Deployment](#-8-deployment)

## 🌐 Overview 
In our confidential container group example, we will deploy the SKR sidecar along with a set of test containers that exercise and test the REST API:



| Container             | Entry Point                           | Environment Variables                                                                                                            |
|---------------------|----------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| `skr sidecar`       | `/skr.sh`                              | - `SkrSideCarArgs`: passes the certificate cache endpoint information. |
| `attest/raw test`   | `/tests/skr/attest_client.sh`          | - `AttestClientRuntimeData`: passes a blob whose `SHA-256` digest will be encoded in the raw attestation report as `report_data`. |
| `attest/maa test`   | `/tests/skr/attest_client.sh`          | - `AttestClientMAAEndpoint`: passes the Microsoft Azure Attestation endpoint which will author the attestation token.<br>- `AttestClientRuntimeData`: passes a blob whose `SHA-256` digest will be encoded in the attestation token as runtime claim. |
| `key/release test`  | `/tests/skr/skr_client.sh`             | - `SkrClientKID`: passes the key identifier of the key to be released from the key vault.<br>- `SkrClientAKVEndpoint`: passes the key vault endpoint from which the key will be released.<br>- `SkrClientMAAEndpoint`: passes the Microsoft Azure Attestation (MAA) endpoint shall author the attestation token required for releasing the secret. The MAA endpoint shall be the same as the one specified in the SKR policy during the key import to the key vault. |

  
For issues during setup, refer to the Troubleshooting guide: `examples\encfs\TROUBLESHOOTING.md`


## 🧰 Policy generation

Deploying a confidential container group requires generating a security policy that restricts what containers can run within the container group.

To generate security policies: 
- [ ] Install the [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest#install)
- [ ] Then, install the `confcom` CLI extension [here](https://github.com/Azure/azure-cli-extensions/tree/main/src/confcom/azext_confcom#microsoft-azure-cli-confcom-extension-examples) (instructions under 'extension examples').

There are two options for generating security policies:

1. The ARM template can be used directly to generate a security policy.
2. A config file can be used to generate a policy fragment for a particular image (this is called "image-attached fragments" and is useful in cases where stable key release policies are required).

<br>

---

### Option 1 - ARM Template

The following command generates a security policy and automatically injects it into the template.
Include the `--debug-mode` option so the generated policy allows shelling into the container to see the released key in this example. 

Note that `--debug-mode` is only used as an example and **not recommended for production**.


```shell
az confcom acipolicygen -a aci-arm-template.json --debug-mode
```
More information on ARM templates [here](https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/overview).

<br>

---

### Option 2 - Image-attached fragments

The following command generates a security policy and attaches it to the container in an OCI-compliant registry like Azure Container Registry (ACR). To do this, a copy of the SKR container must be made and pushed to an ACR instance with write access. This can be done with:

```bash
az acr login -n <my-registry>
docker pull mcr.microsoft.com/aci/skr:2.9
docker tag mcr.microsoft.com/aci/skr:2.9 <my-registry>.azurecr.io/skr:2.9
docker push <my-registry>.azurecr.io/skr:2.9
```

Create a configuration file with the container details as illustrated below:

```json
{
    "containers": [
          {
            "name": "skr-sidecar-container",
            "properties": {
              "command": [
                "/skr.sh"
              ],
              "environmentVariables": [
                {
                  "name": "LogFile",
                  "value": "<optional-logfile-path>"
                },
                {
                  "name": "LogLevel",
                  "value": "<optional-loglevel-trace-debug-info-warning-error-fatal-panic>"
                }
              ],
              "image": "<my-registry>/skr:2.9"
            }
        }
    ]
}
```

Save this file to the current directory as `fragment_config.json`.
To verify that a policy fragment is coming from a valid source, it must be COSE signed via a key and certificate chain.
Instructions and guidelines on how to do that for a development deployment are given [here](https://github.com/Azure/azure-cli-extensions/tree/main/src/confcom/samples/certs/README.md) but other methods to generate a cert chain and key may be used.
The flag `--namespace` is used to name the policy fragment, guidelines on what is a valid namespace are found [here](https://www.openpolicyagent.org/docs/policy-language#packages).
Then run the command to generate a policy fragment and upload it to the image registry:

```bash
az confcom acifragmentgen -i fragment_config.json \
      --debug-mode \
      --upload-fragment \
      --image-target <my-registry>/skr:2.9 \
      --key <path-to-my-key> \
      --chain <path-to-my-cert-chain> \
      --svn 1 \
      --namespace <my-namespace>
```

After this policy fragment is generated and uploaded, there are two more steps to allow the ARM template to reference this uploaded file.
The first is to create an import statement for the policy fragment with the following command:

```bash
az confcom acifragmentgen --generate-import --image <my-registry>/skr:2.9 --fragments-json fragments.json --minimum-svn 1
```

Which will output the fragment's import statement in json format to the file `fragments.json`.
In this command `--minimum-svn` defines the minimum allowable security version number (a monotonically increasing integer).
This SVN is chosen when creating a policy fragment, and should be increased anytime a security vulnerability is patched.

Example output:

```json
{
    "fragments": [
        {
        "feed": "<my-registry>/skr",
        "includes": [
            "containers",
            "fragments"
        ],
        "issuer": "did:x509:0:sha256:0NWnhcxjUwmwLCd7A-PubQRq08ig3icQxpW5d2f4Rbc::subject:CN:Contoso",
        "minimum_svn": "1"
        }
    ]
}
```

To generate the security policy for the ARM template, run the following command:

```bash
az confcom acipolicygen -a aci-arm-template.json --include-fragments --fragments-json fragments.json
```

This will insert the container policy into the ARM template and include the mentioned fragments in the `fragments.json` file.
The last step can also be performed with YAML files for VN2 scenarios using `--virtual-node-yaml`, or another json config file using `-i` in place of `-a`.

The ARM template file includes three entries: (i) SKR sidecar container which enables the /skr.sh as entry point command and the environment variable SkrSideCarArgs used by the script, (ii) attest_client container which enables the /tests/skr/attest_client.sh as entry point command and a set of environment variables used by the script and whose names begin with AttestClient, and  (iii) skr_client container which enables the /tests/skr_client.sh as entry point command and a set of environment variables used by the script and whose names begin with SkrClient.
Please note that:

- The policy includes one entry for both attestation tests, as both tests use the same entry point and a superset of environment variables enabled by the AttestClient regular expression.

<br>

## 🚀 Quickstart -  Running SKR Sidecar on Confidential ACI

Here is an example of running SKR sidecar on confidential ACI.
- The MAA endpoint is the value of env var [`SkrClientMAAEndpoint`](aci-arm-template.json?plain=1#L55).
- The managed HSM instance endpoint corresponds to [`SkrClientAKVEndpoint`](aci-arm-template.json?plain=1#L59).
- We will also import a key into managed HSM under the name [`doc-sample-key-release`](aci-arm-template.json?plain=1#L64)

<br> 

### 🔗 1. Obtain an Attestation Endpoint

Below are the MAA endpoints (as of April 2025) for the four regions in which Confidential Containers on AKS is currently available.
  - East US: `sharedeus.eus.attest.azure.net`
  - West US: `sharedwus.wus.attest.azure.net`
  - North Europe: `sharedneu.neu.attest.azure.net`
  - West Europe: `sharedweu.weu.attest.azure.net`
  
<br> 

- [ ] Use the following command to check for other available attestation providers:
  ```shell
  az attestation list
  ```

If at this point, you don't already have a valid attestation endpoint:
- [ ] Create a [Microsoft Azure Attestation](https://learn.microsoft.com/en-us/azure/attestation/quickstart-azure-cli) endpoint to author the attestation token 

Once you have decided on a provider:
  - [ ] Run the following command to get the endpoint value:
    ```shell
    az attestation show --name "<ATTESTATION PROVIDER NAME>" --resource-group "<RESOURCE_GROUP>"
    ```

- [ ] Copy the AttestURI endpoint value (**WITHOUT** https://) to: 
  - [Attestation Authority endpoint](importkeyconfig.json#L6) in `importkeyconfig.json`
  - [SkrClientMAAEndpoint](aci-arm-template.json#L56) and [AttestClientMAAEndpoint](aci-arm-template.json#L106) in `aci-arm-template.json`

<br>

### 🔐 2. Azure Key Vault (AKV) and User Managed Identity

> #### Notes on Different Vault Types:
>   - `Standard`: Software-protected keys only. Lower cost. Suitable for general-purpose secrets and keys.
>   - `Premium`: Supports HSM-backed keys (FIPS 140-2 Level 2). Required for higher security and compliance.
>   - `Managed HSM`: Dedicated HSM cluster. Offers full control over key lifecycle and compliance with stricter regulatory requirements.

####  Azure Key Vault CLI Command Summary

| Action             | Standard Vault                                                                                      | Premium Vault (HSM-backed keys)                                                                                      | Managed HSM                                                                                          |
|--------------------|-----------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| **Delete Vault**   | `az keyvault delete --name "<AKV_NAME>" --resource-group "<RESOURCE_GROUP>"`                 | Same as Standard                                                                                                     | `az keyvault delete-hsm --name "<HSM_NAME>" --resource-group "<RESOURCE_GROUP>"`                      |
| **Purge Vault**    | `az keyvault purge --name "<AKV_NAME>"`                                                      | Same as Standard                                                                                                     | `az keyvault purge-hsm --name "<HSM_NAME>"`                                                           |
| **Create Key**     | `az keyvault key create --vault-name "<AKV_NAME>" --name "<KEY_NAME>" --protection software` | `az keyvault key create --vault-name "<AKV_NAME>" --name "<KEY_NAME>" --protection hsm`                        | `az keyvault key create --hsm-name "<HSM_NAME>" --name "<KEY_NAME>" --kty RSA-HSM`                    |
| **Delete Key**     | `az keyvault key delete --vault-name "<AKV_NAME>" --name "<KEY_NAME>"`                       | Same as Standard                                                                                                     | `az keyvault key delete --hsm-name "<HSM_NAME>" --name "<KEY_NAME>"`                                 |
| **Purge Key**      | `az keyvault key purge --vault-name "<AKV_NAME>" --name "<KEY_NAME>"`                        | Same as Standard                                                                                                     | `az keyvault key purge --hsm-name "<HSM_NAME>" --name "<KEY_NAME>"`                                  |

---

For more information on CLI commands, use this [reference](https://learn.microsoft.com/en-us/cli/azure/keyvault?view=azure-cli-latest).

<br>


#### 2.1 Create an AKV

- [ ] Use one of the following commands to create your vault with the desired level of security *(Continue to use that vault type for the remainder of the example)*:
  ```shell
  # Standard
  az keyvault create --name "<AKV_NAME>" --resource-group "<RESOURCE_GROUP>" --location "<REGION>" --sku standard

  # Premium
  az keyvault create --name "<AKV_NAME>" --resource-group "<RESOURCE_GROUP>" --location "<REGION>" --sku premium   

  # mHSM
  az keyvault create --name "<HSM_NAME>" --resource-group "<RESOURCE_GROUP>" --location "<REGION>" --sku premium --hsm-name "<>"
  ```
  For more information on vault types, read [Vault (AKV)](https://learn.microsoft.com/en-us/azure/key-vault/general/overview) and [mHSM resource](https://docs.microsoft.com/en-us/azure/key-vault/managed-hsm/overview).

- [ ] Replace [SkrClientAKVEndpoint](aci-arm-template.json#L65) in `aci-arm-template.json` with the appropriate endpoint based on the chosen vault:
  - **AKV**: `<AKV_NAME>.vault.azure.net`
  - **mHSM**: `<HSM_NAME>.managedhsm.azure.net`


- [ ] (Optional) If you wish to upgrade from standard to premium, run:
  ```shell
  az keyvault update --set properties.sku.name=premium --name "<AKV_NAME>" --resource-group "<RESOURCE_GROUP>" 
  ```

<br>


#### 2.2 Generate a User Managed Identity
After setting up an Azure Key Vault resource: 
- [ ] Generate a user-assigned managed identity [here](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-manage-user-assigned-managed-identities?pivots=identity-mi-methods-azp) that will be attached to the container group so that the containers have the correct access permissions to Azure services and resources. Or, run: 
  ```shell
  az identity create --name "<MANAGED_ID_NAME>" --resource-group "<RESOURCE_GROUP>" --location "<REGION>"
  ```

  If using AKV ***key vault***: 
  - [ ] Assign the `Key Vault Crypto Service Release User` role to your managed identity <br> 
  (previously `Key Vault Crypto Officer` and `Key Vault Crypto User`) 
  
  ```shell
  az role assignment create \
  --assignee-object-id "<PRINCIPAL_ID>" \ 
  --role "Key Vault Crypto Service Release User" \
  --scope "/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RESOURCE_GROUP>/providers/Microsoft.KeyVault/vaults/<AKV_NAME>"
  ```
  

  If using AKV ***managed HSM***: 
  - [ ] Assign the `Managed HSM Crypto Service Release User` role to your managed identity <br> 
  (previously `Managed HSM Crypto Officer` and `Managed HSM Crypto User`) 
  ```shell
  az role assignment create \
  --assignee-object-id "<PRINCIPAL_ID>" \
  --role "Managed HSM Crypto Service Release User" \
  --scope "/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RESOURCE_GROUP>/providers/Microsoft.KeyVault/managedHSMs/<HSM_NAME>"
  ```

More information about creating identities can be found [here.](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/)

<br>


#### 2.3 Check User Managed Identity
If you already have a user-assigned managed identity with the appropriate access permissions:
- [ ] Run the following command to list the managed identities for a RESOURCE_GROUP:

  ```shell
  az identity list -g "<RESOURCE_GROUP>"
  ```

  Or, if you know the name of the managed identity **and** the RESOURCE_GROUP:
  - [ ] Run:

    ```shell
    az identity show -g "<RESOURCE_GROUP>" -n "<MANAGED_ID_NAME>"
    ```


- [ ] Replace [managed-identity-with-right-permissions-to-key-vault](aci-arm-template.json#:~:text=%22%3Cmanaged%2Didentity%2Dwith%2Dright%2Dpermissions%2Dto%2Dkey%2Dvault%3E%22) of `aci-arm-template.json` with the identity ID.

<br>


### 🪪 3. Populate Image Registry Credentials

Depending on whether you are using a public or private registry, do **one** of the following:

  - [ ] **Private**: Update the [image registry credentials](aci-arm-template.json?plain=1#L123) in `aci-arm-template.json` in order to access a private container registry. The credential could be either a managed identity or username/password.
      
  - [ ] **Public**: Remove this section - It is not needed for public images.

<br>


### 🪙 4. Obtain the AAD token
- [ ] Use the following command to obtain the AAD token with permission to AKV/mHSM:

  ```shell
  az account get-access-token --resource "https://managedhsm.azure.net" # For mHSM
  az account get-access-token --resource "https://vault.azure.net"      # For AKV
  ```
- [ ] Replace the following with the `accessToken` from the output: 
  - [AAD token](importkeyconfig.json#L11) in `importkeyconfig.json`
  
<br>


### 📝 5. Fill in Key Information
After setting up an Azure Key Vault resource:
- Fill in the `importkeyconfig.json` file with:
  - [ ] a key name **to be created** and imported into the key vault, under [`key.kid`](importkeyconfig.json#L3).
  - [ ] also copy the key name into [`SkrClientKID`](aci-arm-template.json#L74) in the `aci-arm-template.json`.
  - [ ] the [`key-vault-endpoint`](importkeyconfig.json#L9) (**WITHOUT** https://) in the format: `<AKV_NAME>.vault.azure.net` 
    - [ ] If not using a specific [`api_version`](importkeyconfig.json#L9), leave value as an empty string.

- Additionally, fill in (or remove) these optional fields in the `importkeyconfig.json` file: 
  - [ ] [Key derivation](importkeyconfig.json#L14) for RSA keys
  - [ ] [Key type: `RSA-HSM` or `oct-HSM`](importkeyconfig.json#L4)
  
- For the `aci-arm-template.json`:
  - [ ] Run the following command to get the full managed identity, and replace `<managed-identity-with-right-permissions-to-key-vault>` with the output:

    ```shell
    az identity show --name "<MANAGED_ID_NAME>" --resource-group "<RESOURCE_GROUP>" --query id -o tsv
    ```
  - [ ] Remove or fill out `LogFile` and `LogLevel` (under `environmentVariables`)


<br>

### 📄 6. Generate Security Policy

At this point, the `aci-arm-template.json` file should be filled out except for the `ccepolicy` field.

After installing the [Azure `confcom` CLI extension](#policy-generation):
- [ ] Run the following command to generate the security policy and include the `--debug-mode` option so that the policy allows users to shell into the container.

  ```shell
  az confcom acipolicygen -a "aci-arm-template.json" --debug-mode
  ```

- [ ] Accept the prompt to automatically populate the [`cce policy`](aci-arm-template.json#L142) field of `aci-arm-template.json.`
      
  This should output the `SHA-256` digest of the security policy.

  - [ ] Copy it and replace the [`hash-digest-of-the-security-policy`](importkeyconfig.json#L22) string of the `importkeyconfig.json` file.

<br>


### 📤 7. Import Keys into mHSM/AKV

Once the key vault resource is ready and the `importkeyconfig.json` file is completely filled out, the user can import `RSA-HSM` or `oct-HSM` keys into it using the `importkey` tool placed under `<parent_repo_dir>/tools/importkey` as discussed in the tools' [readme file](https://github.com/microsoft/confidential-sidecar-containers/tree/main/tools/importkey).

To import the key into AKV/mHSM:
- [ ] Use the following command from the `/examples/skr/aci/` directory:

  ```shell
  go run "../../../tools/importkey/main.go" -c "importkeyconfig.json"
  ```
  - [ ] Use this option to see the key get released: `-kh /path/to/encryptionKeyFile`

Upon successful import completion, you should see something similar to the following:

```json
[34 71 33 117 113 25 191 84 199 236 137 166 201 103 83 20 203 233 66 236 121 110 223 2 122 99 106 20 22 212 49 224]
https://<mhsm-name>.managedhsm.azure.net/keys/doc-sample-key-release/8659****0cdff08
{"version":"1.0.0","anyOf":[{"authority":"<authority-url-name>","allOf":[{"claim":"x-ms-sevsnpvm-hostdata","equals":"aaa7***7cc09d"},{"claim":"x-ms-compliance-status","equals":"azure-compliant-uvm"},{"claim":"x-ms-sevsnpvm-is-debuggable","equals":"false"},{"claim":"x-ms-sevsnpvm-vmpl","equals":"0"}]}]}
```

- [ ] Use the following commands to verify the key has been successfully imported:

```shell
az account set --subscription "<SUBSCRIPTION ID>"
az keyvault key list --hsm-name   "<HSM_NAME>" -o table  # For mHSM
az keyvault key list --vault-name "<AKV_NAME>" -o table  # For AKV
```

<br>


### 📦 8. Deployment

You can deploy using the CLI ***or*** Azure Portal:

CLI:

  ```shell
  az deployment group create --resource-group "<RESOURCE_GROUP>" --template-file "aci-arm-template.json"
  ```

Azure Portal: 
- [ ] Go to Azure portal and click on `deploy a custom template`
- [ ] Click `Build your own template in the editor`
      
    By this time, the `aci-arm-template.json` file should be completely filled out.
- [ ] Copy and paste the ARM template into the field to start a deployment.

<br>


Once the deployment is done:
- [ ] Verify the key has been successfully released, by connecting to the shell of the `skr-sidecar-container` container
- [ ] Check log.txt and you should see the following log message:

    ```text
    level=debug msg=Releasing key blob: {doc-sample-key-release}
    ``` 

Alternatively, you can:
- [ ] Shell into the container `test-skr-client-hsm-skr` and the released key is in `keyrelease.out`.


- ??? TODO: Create local copies of the JSON files with my changes so I can update and commit only the templates using them as a reference - try to uncommit any additional files too