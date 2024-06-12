# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

import requests
import uuid
import os
import unittest
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from attestation import validate_attestation

from c_aci_testing.aci_get_ips import aci_get_ips
from c_aci_testing.aci_param_set import aci_param_set
from c_aci_testing.target_run import target_run_ctx

class AttestationTest(unittest.TestCase):
    def test_attestation(self):

        target_dir = os.path.realpath(os.path.dirname(__file__))
        id = os.getenv("ID", str(uuid.uuid4()))

        aci_param_set(
            file_path=os.path.join(target_dir, "attestation.bicepparam"),
            key="attestationEndpoint",
            value=f'\'https://{os.environ["ATTESTATION_ENDPOINT"]}\''
        )

        with target_run_ctx(
            target=target_dir,
            name=id,
            tag=os.getenv("TAG") or id,
            follow=False,
            cleanup=True,
        ) as deployment_ids:
            ip_address = aci_get_ips(ids=deployment_ids[0])

            input_report_data = "EXAMPLE"

            attestation = requests.get(
                f"http://{ip_address}:8000/get_attestation?report_data={input_report_data}",
            )
            assert attestation.status_code == 200

            cert_chain = requests.get(
                f"http://{ip_address}:8000/get_cert_chain",
            )
            assert cert_chain.status_code == 200

            validate_attestation(
                attestation_bytes=attestation.content,
                certificate_chain=cert_chain.content,
                expected_report_data=input_report_data,
            )

        # Cleanup happens after block has finished


if __name__ == "__main__":
    unittest.main()
