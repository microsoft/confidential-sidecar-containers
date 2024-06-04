# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

from base64 import b64encode, urlsafe_b64encode
import hashlib
import json
import requests
import binascii
import subprocess
import tempfile


def generate_key():
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
                    ],
                }
            ],
        }
    )

def deploy_key(
    key_id: str,
    attestation_endpoint: str,
    hsm_endpoint: str,
    key_data: bytes,
    security_policy: str,
):

    response = requests.put(
        url=f"https://{hsm_endpoint}/keys/{key_id}?api-version=7.4",
        data=json.dumps(
            {
                "key": {
                    "kty": "oct-HSM",
                    "k": urlsafe_b64encode(binascii.unhexlify(key_data)).decode(),
                    "key_size": 256,
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
    print(f"Deployed key {key_id} into the HSM")
