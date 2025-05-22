# Attestation and Secure Key Release Sidecar ACI Example

## Table of Contents

- [Policy generation](#policy-generation)
  - [Option 1 - ARM Template](#option-1---arm-template)
  - [Option 2 - Image-attached fragments](#option-2---image-attached-fragments)
- [Step by Step Example](#step-by-step-example)

In our confidential container group example, we will deploy the skr sidecar along with a set of test containers that exercise and test the REST API.

- **skr sidecar.** The sidecar’s entry point is /skr.sh which uses the SkrSideCarArgs environment variable to pass the certificate cache endpoint information.
- **attest/raw test.** The sidecar’s entry point is /tests/skr/attest_client.sh which uses the AttestClientRuntimeData environment variable to pass a blob whose sha-256 digest will be encoded in the raw attestation report as report_data.
- **attest/maa test.** The sidecar’s entry point is /tests/skr/attest_client.sh which uses two environment variables: (i) AttestClientMAAEndpoint passes the Microsoft Azure Attestation endpoint which will author the attestation token, (ii) AttestClientRuntimeData passes a blob whose sha-256 digest will be encoded in the attestation token as runtime claim.
- **key/release test.** The sidecar’s entry point is /tests/skr/skr_client.sh which uses the three environment variables: (i) SkrClientKID passes the key identifier of the key to be released from the key vault, (ii) SkrClientAKVEndpoint passes the key vault endpoint from which the key will be released, and (iii) SkrClientMAAEndpoint passes the Microsoft Azure Attestation endpoint shall author the attestation token required for releasing the secret.
The MAA endpoint shall be the same as the one specified in the SKR policy during the key import to the key vault.

### Policy generation

Deploying a confidential container group requires generating a security policy that restricts what containers can run within the container group.
To generate security policies, install the Azure `confcom` CLI extension by following the instructions [here under extension examples](https://github.com/Azure/azure-cli-extensions/tree/main/src/confcom/azext_confcom#microsoft-azure-cli-confcom-extension-examples).

There are two options for generating security policies:

1. The ARM template can be used directly to generate a security policy.
2. A config file can be used to generate a policy fragment for a particular image (this is called "image-attached fragments" and is useful in cases where stable key release policies are required).

#### Option 1 - ARM Template

The following command generates a security policy and automatically injects it into the template.
Include the `--debug-mode` option so the generated policy allows shelling into container to see the released key in this example. Note that `--debug-mode` is only used as an example and not recommended for production.

```shell
az confcom acipolicygen -a template.json --debug-mode
```

#### Option 2 - Image-attached fragments

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
az confcom acipolicygen -a template.json --include-fragments --fragments-json fragments.json
```

This will insert the container policy into the ARM template and include the mentioned fragments in the `fragments.json` file.
The last step can also be performed with YAML files for VN2 scenarios using `--virtual-node-yaml`, or another json config file using `-i` in place of `-a`.

The ARM template file includes three entries: (i) skr sidecar container which enables the /skr.sh as entry point command and the environment variable SkrSideCarArgs used by the script, (ii) attest_client container which enables the /tests/skr/attest_client.sh as entry point command and a set of environment variables used by the script and whose names begin with AttestClient, and  (iii) skr_client container which enables the /tests/skr_client.sh as entry point command and a set of environment variables used by the script and whose names begin with SkrClient.
Please note that:

- The policy includes one entry for both attestation tests, as both tests use the same entry point and a superset of environment variables enabled by the AttestClient regular expression.

### Step by Step Example

Here is an example of running skr sidecar on confidential ACI.
The MAA endpoint is the value of env var [`SkrClientMAAEndpoint`](aci-arm-template.json?plain=1#L55).
The managed HSM instance endpoint corresponds to [`SkrClientAKVEndpoint`](aci-arm-template.json?plain=1#L59).
We will also import a key into managed HSM under the name [`doc-sample-key-release`](aci-arm-template.json?plain=1#L64)

#### 1. Obtain an Attestation Endpoint

If you don't already have a valid attestation endpoint, create a [Microsoft Azure Attestation](https://learn.microsoft.com/en-us/azure/attestation/overview) endpoint to author the attestation token and run the following command to get the endpoint value:

```shell
az attestation show --name "<ATTESTATION PROVIDER NAME>" --resource-group "<RESOURCE GROUP>"
```

Copy the AttestURI endpoint value (**WITHOUT** https://) to the [Attestation Authority endpoint](importkeyconfig.json#L6) in `importkeyconfig.json` and to [SkrClientMAAEndpoint](aci-arm-template.json#L56) and [AttestClientMAAEndpoint](aci-arm-template.json#L106) in `aci-arm-template.json`.

#### 2. Generate User Managed Identity

The user needs to instantiate an Azure Key Vault resource that supports storing keys in an HSM: a [Premium vault](https://learn.microsoft.com/en-us/azure/key-vault/general/overview) or an [MHSM resource](https://docs.microsoft.com/en-us/azure/key-vault/managed-hsm/overview).

After setting up an Azure Key Vault resource, generate a user-assigned managed identity that will be attached to the container group so that the containers have the correct access permissions to Azure services and resources.
The managed identity needs *Key Vault Crypto Service Release User* role (previously *Key Vault Crypto Officer* and *Key Vault Crypto User*) if using AKV key vault or *Managed HSM Crypto Service Release User* role (previously *Managed HSM Crypto Officer* and *Managed HSM Crypto User*) for keys if using AKV managed HSM.
More information about creating identities can be found [here.](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/)

If you already have a user-assigned managed identity with the appropriate access permissions, run the following command to list the managed identities for a resource group:

```shell
az identity list -g <RESOURCE GROUP>
```

Or you can use the following command if you know the name of the managed identity and the resource group:

```shell
az identity show -g <RESOURCE GROUP> -n <MANAGED IDENTITY NAME>
```

Replace [managed-identity-with-right-permissions-to-key-vault](aci-arm-template.json#:~:text=%22%3Cmanaged%2Didentity%2Dwith%2Dright%2Dpermissions%2Dto%2Dkey%2Dvault%3E%22) of `aci-arm-template.json` with the identity ID.

#### 3. Populate Image Registry Credentials

Update the [image registry credentials](aci-arm-template.json?plain=1#L123) on the ARM template in order to access a private container registry.
The credential could be either a managed identity or username/password.
This section is not needed for public images.

#### 4. Obtain the AAD token

The AAD token with permission to AKV/mHSM can be obtained with the following command:

```shell
az account get-access-token --resource https://managedhsm.azure.net
```

Replace [AAD token](importkeyconfig.json#L11) in `importkeyconfig.json` and [SkrClientAKVEndpoint](aci-arm-template.json#L60) in `aci-arm-template.json` with the output accessToken.

#### 5. Fill in Key Information

After setting up an Azure Key Vault resource, fill in the `importkeyconfig.json` file with the name of the key to be created and imported into the key vault [Key name](importkeyconfig.json#L3).

Additionally, fill in the optional [key derivation](importkeyconfig.json#L14) for RSA keys and [Key type: `RSA-HSM` or `oct-HSM`](importkeyconfig.json#L4) fields or remove these fields from the `importkeyconfig.json` file.

Copy the key name into [SkrClientKID](aci-arm-template.json#L64) in the `aci-arm-template.json`.

#### 6. Generate Security Policy

At this point, the `aci-arm-template.json` file should be filled out except for the `ccepolicy` field.
After installing the [Azure `confcom` CLI extension](#policy-generation), run the following command to generate the security policy and include the `--debug-mode` option so that the policy allows users to shell into the container.

```shell
az confcom acipolicygen -a aci-arm-template.json --debug-mode
```

This should prompt you to automatically populate the [cce policy](aci-arm-template.json#L142) field of `aci-arm-template.json.`

This should output the sha256 digest of the security policy.
Copy it and replace the [hash-digest-of-the-security-policy](importkeyconfig.json#L22) string of the `importkeyconfig.json` file.

#### 7. Import Keys into mHSM/AKV

Once the key vault resource is ready and the `importkeyconfig.json` file is completely filled out, the user can import `RSA-HSM` or `oct-HSM` keys into it using the `importkey` tool placed under `<parent_repo_dir>/tools/importkey` as discussed in the tools' [readme file](https://github.com/microsoft/confidential-sidecar-containers/tree/main/tools/importkey).

A fake encryption key is used in the command below to see the key get released.
To import the key into AKV/mHSM, use the following command:

```go
go run /tools/importkey/main.go -c importkeyconfig.json -kh /path/to/encryptionKeyFile
```

Upon successful import completion, you should see something similar to the following:

```json
[34 71 33 117 113 25 191 84 199 236 137 166 201 103 83 20 203 233 66 236 121 110 223 2 122 99 106 20 22 212 49 224]
https://<mhsm-name>.managedhsm.azure.net/keys/doc-sample-key-release/8659****0cdff08
{"version":"1.0.0","anyOf":[{"authority":"<authority-url-name>","allOf":[{"claim":"x-ms-sevsnpvm-hostdata","equals":"aaa7***7cc09d"},{"claim":"x-ms-compliance-status","equals":"azure-compliant-uvm"},{"claim":"x-ms-sevsnpvm-is-debuggable","equals":"false"},{"claim":"x-ms-sevsnpvm-vmpl","equals":"0"}]}]}
```

In this case, use the following commands to verify the key has been successfully imported:

```shell
az account set --subscription "<SUBSCRIPTION>"
az keyvault key list --hsm-name <MHSM NAME> -o table
```

#### 8. Deployment

Go to Azure portal and click on `deploy a custom template`, then click `Build your own template in the editor`.
By this time, the `aci-arm-template.json` file should be completely filled out.
Copy and paste the ARM template into the field start a deployment.
Once deployment is done, to verify the key has been successful released, shell into the `skr-sidecar-container` container and see the log.txt and you should see the following log message:

```text
level=debug msg=Releasing key blob: {doc-sample-key-release}
```

Alternatively, you can shell into the container `test-skr-client-hsm-skr` and the released key is in keyrelease.out.
