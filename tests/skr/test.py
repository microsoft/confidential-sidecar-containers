# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

import binascii
import hashlib
import re
import struct
import subprocess
import sys
import tempfile
import requests
import uuid
import os
import unittest
import base64
import json

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from attestation.attestation import SNP_REPORT_STRUCTURE
from key import generate_key, deploy_key, generate_release_policy

from c_aci_testing.target_run import target_run_ctx
from c_aci_testing.aci_get_ips import aci_get_ips

def get_grpc_response(raw_response: bytes):
    return json.loads(
        re.findall(
            r"Response contents:\s*(\{.*?\})",
            raw_response.decode(),
            re.DOTALL
        )[0]
    )

def check_report_data(report: str, expected_report_data: str):

    # Report data isn't returned as Hex, so we unhex around it
    skr_report = struct.unpack_from(
        f"<{SNP_REPORT_STRUCTURE}",
        (
            binascii.unhexlify(report[:160])
            + report[160:224].encode()  # Report Data
            + binascii.unhexlify(report[224:])
        ),
        0,
    )

    # SKR Sidecar decodes the base64 string and then hashes it before
    # providing it to the SNP Attestation
    seen_report_data = skr_report[10].rstrip(b"\x00").decode()
    expected_report_data = hashlib.sha256(expected_report_data).hexdigest()
    print(f"Checking seen report data: {seen_report_data}")
    print(f"Matches provided report data: {expected_report_data}")
    assert seen_report_data == expected_report_data

class SkrTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):

        cls.target_dir = os.path.realpath(os.path.dirname(__file__))
        cls.id = os.getenv("ID", str(uuid.uuid4()))
        cls.tag = os.getenv("TAG") or cls.id

        cls.attestation_endpoint = "confidentialsidecars.weu.attest.azure.net"
        cls.hsm_endpoint = "cacisidecars.managedhsm.azure.net"

        cls.aci_context = target_run_ctx(
            target=cls.target_dir,
            name=cls.id,
            tag=cls.tag,
            follow=False,
            cleanup=True,
        )

        cls.skr_id, = cls.aci_context.__enter__()
        cls.skr_ip = aci_get_ips(ids=cls.skr_id)

    @classmethod
    def tearDownClass(cls):
        cls.aci_context.__exit__(None, None, None)

    def test_skr_http_status(self):

        status_response = requests.get(
            f"http://{self.skr_ip}:8000/status",
        )
        print(f"Response from status check: {status_response.content}")
        assert status_response.status_code == 200

    def test_skr_http_attest_raw(self):

        input_report_data = b"EXAMPLE"
        attestation_resp = requests.post(
            url=f"http://{self.skr_ip}:8000/attest/raw",
            headers={
                "Content-Type": "application/json",
            },
            data=json.dumps(
                {
                    "runtime_data": base64.urlsafe_b64encode(
                        input_report_data
                    ).decode(),
                }
            ),
        )
        print(f"Response from attestation check: {attestation_resp.content}")
        assert attestation_resp.status_code == 200, attestation_resp.content.decode()

        check_report_data(
            report=json.loads(attestation_resp.content.decode())["report"],
            expected_report_data=input_report_data,
        )

    def test_skr_http_attest_maa(self):

        test_key = json.dumps(
            {
                "keys": [
                    {
                        "key_ops": ["encrypt"],
                        "kid": "test-key",
                        "kty": "oct-HSM",
                        "k": "example",
                    }
                ]
            }
        )

        maa_response = requests.post(
            url=f"http://{self.skr_ip}:8000/attest/maa",
            headers={
                "Content-Type": "application/json",
            },
            data=json.dumps(
                {
                    "maa_endpoint": self.attestation_endpoint,
                    "runtime_data": base64.urlsafe_b64encode(test_key.encode()).decode(),
                }
            ),
        )

        assert maa_response.status_code == 200, maa_response.content.decode()
        assert json.loads(maa_response.content.decode())["token"] != ""

    def test_skr_http_key_release(self):

        # Deploy a Key to the mHSM
        key_id = f"{self.id}-key"
        with open(os.path.join(os.path.realpath(os.path.dirname(__file__)), "policy_skr.rego")) as f:
            deploy_key(
                key_id=key_id,
                attestation_endpoint=self.attestation_endpoint,
                hsm_endpoint=self.hsm_endpoint,
                key_data=generate_key(),
                security_policy=f.read(),
            )

        skr_response = requests.post(
            url=f"http://{self.skr_ip}:8000/key/release",
            headers={
                "Content-Type": "application/json",
            },
            data=json.dumps(
                {
                    "maa_endpoint": self.attestation_endpoint,
                    "akv_endpoint": self.hsm_endpoint,
                    "kid": key_id,
                }
            ),
        )
        assert skr_response.status_code == 200, skr_response.content.decode()
        assert json.loads(json.loads(skr_response.content.decode())["key"])["k"] != ""

    def test_skr_grpc_say_hello(self):

        response = requests.get(
            f"http://{self.skr_ip}:8000/say_hello",
        )
        print(f"Response from say_hello check: {response.content.decode()}")
        assert response.status_code == 200

        assert get_grpc_response(response.content)["message"] == "Hello GRPC interface test!"

    def test_skr_grpc_get_report(self):

        input_report_data = b"EXAMPLE"
        response = requests.get(
            f"http://{self.skr_ip}:8000/get_report",
            headers={
                "Content-Type": "application/json",
            },
            data=json.dumps(
                {
                    "runtime_data": base64.urlsafe_b64encode(input_report_data).decode(),
                }
            ),
        )
        print(f"Response from get_report check: {response.content.decode()}")
        assert response.status_code == 200

    def test_skr_grpc_unwrap_key(self):

        # Generate a key in the HSM
        key_id = f"{self.id}-wrapping-key"
        with open(os.path.join(os.path.realpath(os.path.dirname(__file__)), "policy_skr.rego")) as f:
            security_policy = generate_release_policy(
                attestation_endpoint=self.attestation_endpoint,
                host_data=hashlib.sha256(f.read().encode()).hexdigest()
            )
            subprocess.check_call([
                "az", "keyvault", "key", "create",
                "--id", f"https://{self.hsm_endpoint}/keys/{key_id}",
                "--ops", "wrapKey", "unwrapkey", "encrypt", "decrypt",
                "--kty", "RSA-HSM", "--size", "3072", "--exportable",
                "--policy", f"{security_policy}"])

        # Download the public key
        payload = b"Oceans are full of water\nHorses have 4 legs"
        with tempfile.TemporaryDirectory() as temp_dir:

            in_file_path = os.path.join(temp_dir, "in.txt")
            with open(in_file_path, "wb") as in_file:
                in_file.write(payload)

            public_key_path = os.path.join(temp_dir, f"{key_id}-pub.pem")
            subprocess.check_call([
                "az", "keyvault", "key", "download",
                "--hsm-name", f'{self.hsm_endpoint.split(".")[0]}',
                "--name", key_id,
                "--f", public_key_path])

            key_info_path = os.path.join(temp_dir, f"{key_id}-info.json")
            with open(key_info_path, "w") as key_info_file:
                key_info_file.write(json.dumps(
                    {
                        "public_key_path": public_key_path,
                        "kms_endpoint": self.hsm_endpoint,
                        "attester_endpoint": self.attestation_endpoint,
                    }
                ))

            # Encrypt a payload with the public key
            out_file_path = os.path.join(temp_dir, "out.txt")
            subprocess.check_call([
                "docker", "compose", "run",
                "-v", "/tmp:/tmp",
                "sidecar",
                "/bin/skr",
                "-infile", in_file_path,
                "-keypath", os.path.join(temp_dir, key_id),
                "-outfile", out_file_path,
            ], cwd=self.target_dir, env={**os.environ, "TAG": self.tag})
            with open(out_file_path) as out_file:
                wrapped_payload = out_file.read()

        response = requests.get(
            f"http://{self.skr_ip}:8000/unwrap_key",
            headers={
                "Content-Type": "application/json",
            },
            data=json.dumps(
                {
                    "wrapped_data": wrapped_payload,
                }
            ),
        )
        print(f"Response from unwrap_key check: {response.content.decode()}")
        assert response.status_code == 200

        unwrapped_data = base64.b64decode(
            json.loads(
                base64.b64decode(
                    get_grpc_response(response.content)["KeyProviderKeyWrapProtocolOutput"]
                ).decode()
            )["keyunwrapresults"]["optsdata"]
        ).decode()
        print(f"Unwrapped data: {unwrapped_data}")
        assert unwrapped_data == payload.decode()


if __name__ == "__main__":
    unittest.main()
