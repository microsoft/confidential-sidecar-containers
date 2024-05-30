# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

import unittest
import os
import uuid
import requests
import sys

from c_aci_testing.target_run import target_run_ctx
from c_aci_testing.aci_get_ips import aci_get_ips

sys.path.append(os.path.dirname(os.path.realpath(__file__)))
from attestation import validate_attestation

class ExampleTest(unittest.TestCase):
    def test_example(self):

        target_dir = os.path.realpath(os.path.dirname(__file__))
        id = os.getenv("ID", f"attestation-{str(uuid.uuid4())}")

        with target_run_ctx(
            target=target_dir,
            name=id,
            tag=os.getenv("TAG", id),
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