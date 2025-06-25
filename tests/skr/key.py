# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

from base64 import b64encode, urlsafe_b64encode
import hashlib
import json
import requests
import binascii
import subprocess
import tempfile


def generate_oct_key():
    with tempfile.NamedTemporaryFile() as tmp_key_file:
        print("Generating key file")
        subprocess.check_call(
            f"dd if=/dev/random of={tmp_key_file.name} count=1 bs=32", shell=True
        )

        print("Getting key in hex string format")
        bData = tmp_key_file.read(32)

        subprocess.check_call(f"truncate -s 32 {tmp_key_file.name}", shell=True)
        return binascii.hexlify(bData)

def generate_release_policy(attestation_endpoint, host_data):
    return json.dumps(
        {
            "version": "1.0.0",
            "anyOf": [
                {
                    "authority": f"https://{attestation_endpoint}",
                    "allOf": [
                        {
                            "claim": "x-ms-sevsnpvm-hostdata",
                            "equals": host_data,
                        },
                        {
                            "claim": "x-ms-compliance-status",
                            "equals": "azure-compliant-uvm",
                        },
                        {
                            "claim": "x-ms-sevsnpvm-is-debuggable",
                            "equals": "false",
                        },
                        {
                            "claim": "x-ms-sevsnpvm-vmpl",
                            "equals": "0"
                        },
                    ],
                }
            ],
        }
    )

def deploy_key(
    key_id: str,
    key_ops: list[str],
    attestation_endpoint: str,
    hsm_endpoint: str,
    key_data: bytes,
    security_policy: str,
    kty: str = "oct",
):

    response = requests.put(
        url=f"https://{hsm_endpoint}/keys/{key_id}?api-version=7.4",
        data=json.dumps(
            {
                # https://learn.microsoft.com/en-us/cli/azure/keyvault/key?view=azure-cli-latest#az-keyvault-key-create
                "key": {
                    "kty": kty, # Key types: EC, EC-HSM, RSA, RSA-HSM, oct, oct-HSM
                    "k": urlsafe_b64encode(binascii.unhexlify(key_data)).decode(),
                    "key_size": 256,
                    "key_ops": key_ops, # list of permitted JSON web key operations: decrypt, encrypt, export, import, sign, unwrapKey, verify, wrapKey
                },
                "hsm": True,
                "attributes": {
                    "exportable": True,
                },
                "release_policy": {
                    "contentType": "application/json; charset=utf-8",
                    "data": b64encode(
                        generate_release_policy(
                            attestation_endpoint=attestation_endpoint,
                            host_data=hashlib.sha256(security_policy.encode()).hexdigest(),
                        ).encode()
                    ).decode(),
                    "immutable": False,
                },
            }
        ),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer "
            + json.loads(
                subprocess.check_output(
                    "az account get-access-token --resource https://managedhsm.azure.net",
                    shell=True,
                )
            )["accessToken"],
        },
    )

    assert response.status_code == 200, response.content
    print(f"Deployed {kty} key {key_id} into the HSM")
