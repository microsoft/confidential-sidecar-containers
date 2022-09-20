# Attestation and Secure Key Release Sidecar Example

In our confidential container group example, we will deploy the skr sidecar along with a set of test containers that exercise and test the REST API.
- **skr sidecar.** The sidecar’s entry point is /skr.sh which uses the SkrSideCarArgs environment variable to pass the certificate cache endpoint information.
- **attest/raw test.** The sidecar’s entry point is /tests/attest_client.sh which uses the AttestClientRuntimeData environment variable to pass a blob whose sha-256 digest will be encoded in the raw attestation report as report_data.
- **attest/maa test.** The sidecar’s entry point is /tests/attest_client.sh which uses two environment variables: (i) AttestClientMAAEndpoint passes the Microsoft Azure Attestation endpoint which will author the attestation token, (ii) AttestClientRuntimeData passes a blob whose sha-256 digest will be encoded in the attestation token as runtime claim.
- **key/release test.** The sidecar’s entry point is /tests/skr_client.sh which uses the three environment variables: (i) SkrClientKID passes the key identifier of the key to be released from the MHSM, (ii) SkrClientMHSMEndpoint passes the MHSM endpoint from which the key will be released, and (iii) SkrClientMAAEndpoint passes the Microsoft Azure Attestation endpoint shall author the attestation token required for releasing the secret. The MAA endpoint shall be the same as the one specified in the SKR policy during the key import to the MHSM.

## Preparation

### Managed identity
The user needs to generate a user-assigned managed idenity which will be attached to the container group so that the containers can have the right access permissions to Azure services and resources. More information about creating identities can be found [here.](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/)

### Policy generation
Deploying a confidential container group requires generating a security policy that restricts what containers can run within the container group. There is an az tool available for generation of policies.

`az extension add –source https://acccliazext.blob.core.windows.net/confcom/confcom-<latest-version>-py3-none-any.whl -y`

`az confcom acipolicygen -i policy-in.json -s policy-out.json -orp`

The policy-input file includes three entries: (i) skr sidecar container which whitelists the /skr.sh as entry point command and the environment variable SkrSideCarArgs used by the script, (ii) attest_client container which whitelists the /tests/attest_client.sh as entry point command and a set of environment variables used by the script and whose names begin with AttestClient, and  (iii) skr_client container which whitelists the /tests/skr_client.sh as entry point command and a set of environment variables used by the script and whose names begin with SkrClient. 
Please note that:
- The skr sidecar must be allowed to execute as elevated because it needs access to the PSP which is mounted as a device at /dev/sev. 
- The policy includes one entry for both attestation tests, as both tests use the same entry point and a superset of environment variables whitelisted by the AttestClient regular expression.

### Import key
The user needs to instantiate an [AKV MHSM resource](https://docs.microsoft.com/en-us/azure/key-vault/managed-hsm/overview), and assign the *Managed HSM Crypto Officer* and *Managed HSM Crypto User* roles for /keys to the previously generated user-assigned managed identity.

Once the MHSM resource is ready, the user can import oct-HSM keys into it using the `importkey` tool placed under `<parent_repo_dir>/tools/importkey` after updating the `importkeyconfig.json` with the required information as discussed in the tools' readme file. For instance, the hostdata claim value needs to be set to the hash digest of the security policy, which can be obtained by executing the following command:

`go run <parent_dir>/tools/securitypolicydigest/main.go -p <base64-std-encoded-string-of-security-policy>`

Once the `importkeyconfig.json` is updated, execute the following command:

`cd <parent_dir>/tools/importkey`

`go run main.go -c <parent_dir>/examples/skr/importkeyconfig.json -kh deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef`

### Deployment
The `aci-arm-template.json` provides an ACI ARM template which can be parametrized using the security policy obtained above, the registry name (and credentials if private), the user-assigned managed identity, and the URIs to the endpoints required by the sidecar and test containers, discussed above.