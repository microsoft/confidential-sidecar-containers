#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

import argparse
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
    security_policy: str | None = None,
    kty: str = "oct",
    host_data: str | None = None,
):

    if host_data is None:
        if security_policy is None:
            raise ValueError("security_policy or host_data must be provided")
        host_data = hashlib.sha256(security_policy.encode()).hexdigest()

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
                            host_data=host_data,
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


def _hex_key(value: str) -> bytes:
    try:
        key_data = binascii.unhexlify(value)
    except binascii.Error as error:
        raise argparse.ArgumentTypeError("raw key must be hexadecimal") from error

    if len(key_data) != 32:
        raise argparse.ArgumentTypeError("raw key must contain exactly 32 bytes")
    return key_data


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Deploy an exportable key with an MAA release policy to a managed HSM."
    )
    parser.add_argument("key_id", help="Name for the key in the managed HSM")
    parser.add_argument(
        "raw_key",
        type=_hex_key,
        help="32-byte octet key encoded as 64 hexadecimal characters",
    )
    parser.add_argument(
        "host_data",
        help="Host data value written verbatim to the release policy",
    )
    parser.add_argument(
        "--attestation-endpoint",
        required=True,
        help="Microsoft Azure Attestation endpoint hostname",
    )
    parser.add_argument(
        "--hsm-endpoint",
        required=True,
        help="Managed HSM endpoint hostname",
    )
    parser.add_argument(
        "--key-ops",
        nargs="+",
        default=["encrypt", "decrypt", "wrapKey", "unwrapKey"],
        help="Permitted JSON Web Key operations",
    )
    parser.add_argument(
        "--kty",
        default="oct-HSM",
        help="JSON Web Key type (default: oct-HSM)",
    )
    args = parser.parse_args()

    deploy_key(
        key_id=args.key_id,
        key_ops=args.key_ops,
        attestation_endpoint=args.attestation_endpoint,
        hsm_endpoint=args.hsm_endpoint,
        key_data=binascii.hexlify(args.raw_key),
        host_data=args.host_data,
        kty=args.kty,
    )


if __name__ == "__main__":
    main()
