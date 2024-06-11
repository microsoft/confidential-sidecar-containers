# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

import base64
import json
import subprocess
import tempfile
import requests
import uuid
import os
import unittest
import sys


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from encfs import deploy_encfs
from skr.key import deploy_key, generate_key

from c_aci_testing.aci_is_live import aci_is_live
from c_aci_testing.aci_param_set import aci_param_set
from c_aci_testing.images_build import images_build
from c_aci_testing.images_push import images_push
from c_aci_testing.policies_gen import policies_gen
from c_aci_testing.target_run import target_run_ctx
from c_aci_testing.aci_get_ips import aci_get_ips

class EncFSTest(unittest.TestCase):
    def test_encfs(self):

        target_dir = os.path.realpath(os.path.dirname(__file__))
        id = os.getenv("ID", str(uuid.uuid4()))
        tag = os.getenv("TAG") or id

        attestation_endpoint = os.environ["ATTESTATION_ENDPOINT"]
        hsm_endpoint = os.environ["HSM_ENDPOINT"]
        storage_account_name = os.environ["STORAGE_ACCOUNT_NAME"]
        storage_container_name = os.environ["STORAGE_CONTAINER_NAME"]
        key_id = f"{id}-key"
        test_file_content = "Hello, World!"
        mount_point = "/mnt/remote"
        blob_ids = [f"{id}_block"]

        aci_param_set(
            file_path=os.path.join(target_dir, "encfs.bicepparam"),
            key="sidecarArgsB64",
            value="'" + base64.b64encode(json.dumps({
                "azure_filesystems": [
                    {
                        "mount_point": f'{mount_point}/{blob_id}',
                        "azure_url": f'https://{storage_account_name}.blob.core.windows.net/{storage_container_name}/{blob_id}',
                        "azure_url_private": True,
                        "read_write": True,
                        "key": {
                            "kid": key_id,
                            "authority": {
                            "endpoint": attestation_endpoint
                            },
                            "akv": {
                            "endpoint": hsm_endpoint
                            }
                        }
                    } for blob_id in blob_ids]
            }).encode()).decode() + "'")

        azure_args = {
            "subscription": os.getenv("SUBSCRIPTION"),
            "resource_group": os.getenv("RESOURCE_GROUP")
        }

        image_args = {
            "target": target_dir,
            "registry": os.environ["REGISTRY"],
            "repository": os.getenv("REPOSITORY"),
            "tag": tag,
        }

        if not aci_is_live(**azure_args, name=id):
            images_build(**image_args)
            images_push(**image_args)
            policies_gen(**image_args, **azure_args, deployment_name=id)

            with open(os.path.join(os.path.realpath(os.path.dirname(__file__)), "policy_encfs.rego")) as f:
                key_data = generate_key()
                deploy_key(
                    key_id=key_id,
                    attestation_endpoint=attestation_endpoint,
                    hsm_endpoint=hsm_endpoint,
                    key_data=key_data,
                    security_policy=f.read(),
                )

            with tempfile.NamedTemporaryFile() as test_file:
                test_file.write(test_file_content.encode())
                test_file.flush()
                for blob_type in ("block", "page"):
                    with deploy_encfs(
                        blob_name=f"{id}_{blob_type}",
                        blob_type=blob_type,
                        key=key_data,
                        storage_account_name=storage_account_name,
                        container_name=storage_container_name,
                    ) as filesystem:
                        subprocess.run([
                            "sudo", "cp",
                            test_file.name,
                            os.path.join(filesystem, "test_file.txt")
                        ], check=True)
                        print("test")

        with target_run_ctx(
            target=target_dir,
            name=id,
            tag=os.getenv("TAG") or id,
            follow=False,
            cleanup=False,
            prefer_pull=True, # Images are built earlier, so don't rebuild
            gen_policies=False, # Policy generated to deploy key
        ) as deployment_ids:
            ip_address = aci_get_ips(ids=deployment_ids[0])

            response = requests.get(
                f"http://{ip_address}:8000/read_file?path=test_file.txt",
            )
            assert response.status_code == 200
            assert response.json()["contents"] == test_file_content

        # Cleanup happens after block has finished


if __name__ == "__main__":
    unittest.main()
