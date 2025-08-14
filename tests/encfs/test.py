# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

import argparse
import base64
import binascii
import json
import subprocess
import tempfile
import requests
import uuid
import os
import unittest
import sys


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from skr.key import generate_oct_key, deploy_key
try:
    from .encfs import deploy_encfs
except ImportError:
    from encfs import deploy_encfs

from c_aci_testing.args.parameters.location import parse_location
from c_aci_testing.args.parameters.managed_identity import \
    parse_managed_identity
from c_aci_testing.args.parameters.registry import parse_registry
from c_aci_testing.args.parameters.repository import parse_repository
from c_aci_testing.args.parameters.resource_group import parse_resource_group
from c_aci_testing.args.parameters.subscription import parse_subscription
from c_aci_testing.args.parameters.policy_type import parse_policy_type
from c_aci_testing.tools.aci_get_is_live import aci_get_is_live
from c_aci_testing.tools.aci_param_set import aci_param_set
from c_aci_testing.tools.images_build import images_build
from c_aci_testing.tools.images_push import images_push
from c_aci_testing.tools.policies_gen import policies_gen
from c_aci_testing.tools.target_run import target_run_ctx
from c_aci_testing.tools.aci_get_ips import aci_get_ips

class EncFSTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        target_dir = os.path.realpath(os.path.dirname(__file__))
        id = os.getenv("ID", str(uuid.uuid4()))
        tag = os.getenv("TAG") or id

        attestation_endpoint = os.environ["ATTESTATION_ENDPOINT"]
        hsm_endpoint = os.environ["HSM_ENDPOINT"]
        storage_account_name = os.environ["STORAGE_ACCOUNT_NAME"]
        storage_container_name = os.environ["STORAGE_CONTAINER_NAME"]
        key_id = f"{id}-key"
        cls.test_file_content = "Hello, World!"
        mount_point = "/mnt/remote"
        cls.blobs = [
            (f"{id}-blob1", "page"),
            (f"{id}-blob2", "block"),
        ]

        parser = argparse.ArgumentParser()
        parse_subscription(parser)
        parse_resource_group(parser)
        parse_registry(parser)
        parse_repository(parser)
        parse_location(parser)
        parse_managed_identity(parser)
        parse_policy_type(parser)
        args, _ = parser.parse_known_args()

        azure_args = {
            "subscription": os.getenv("SUBSCRIPTION"),
            "resource_group": os.getenv("RESOURCE_GROUP")
        }

        image_args = {
            "target_path": target_dir,
            "registry": os.environ["REGISTRY"],
            "repository": os.getenv("REPOSITORY"),
            "tag": tag,
        }

        if not aci_get_is_live(**azure_args, deployment_name=id):

            aci_param_set(
                target_path=target_dir,
                parameters={"sidecarArgsB64": base64.urlsafe_b64encode(json.dumps({
                    "azure_filesystems": [
                        {
                            "mount_point": f"{mount_point}/{blob_id}",
                            "azure_url": f"https://{storage_account_name}.blob.core.windows.net/{storage_container_name}/{blob_id}",
                            "azure_url_private": True,
                            "read_write": True if blob_type == "page" else False,
                            "key": {
                                "kid": key_id,
                                "authority": {
                                    "endpoint": attestation_endpoint
                                },
                                "akv": {
                                    "endpoint": hsm_endpoint
                                }
                            }
                        } for blob_id, blob_type in cls.blobs
                    ]
                }).encode()).decode()},
            )

            images_build(**image_args)
            images_push(**image_args)
            policies_gen(
                deployment_name=id,
                policy_type=args.policy_type,
                **image_args,
                **azure_args,
            )

            with open(os.path.join(os.path.realpath(os.path.dirname(__file__)), "policy_encfs.rego")) as f:
                key_data = generate_oct_key()
                deploy_key(
                    key_id=key_id,
                    kty="oct-HSM",
                    key_ops=["encrypt", "decrypt", "wrapKey", "unwrapKey"],
                    attestation_endpoint=attestation_endpoint,
                    hsm_endpoint=hsm_endpoint,
                    key_data=key_data,
                    security_policy=f.read(),
                )

            with tempfile.NamedTemporaryFile() as test_file:
                test_file.write(cls.test_file_content.encode())
                test_file.flush()
                for blob_id, blob_type in cls.blobs:
                    with deploy_encfs(
                        blob_name=blob_id,
                        blob_type=blob_type,
                        key=binascii.unhexlify(key_data),
                        storage_account_name=storage_account_name,
                        container_name=storage_container_name,
                    ) as filesystem:
                        subprocess.run([
                            "sudo", "cp", test_file.name, os.path.join(filesystem, "file.txt")
                        ], check=True)

        args_dict = vars(args)
        args_dict['policy_type'] = 'none' # Policy generated to deploy key

        cls.aci_context = target_run_ctx(
            target_path=os.path.realpath(os.path.dirname(__file__)),
            deployment_name=id,
            tag=id,
            cleanup=True,
            prefer_pull=True, # Images are built earlier, so don't rebuild
            **args_dict,
        )

        cls.encfs_id, = cls.aci_context.__enter__()
        cls.encfs_ip = aci_get_ips(
            deployment_name=id,
            subscription=args.subscription,
            resource_group=args.resource_group,
        )[0]

    @classmethod
    def tearDownClass(cls):
        # Cleans up the ACI instance
        cls.aci_context.__exit__(None, None, None)

    def test_read_rw_encfs(self):

        response = requests.get(
            f"http://{self.encfs_ip}:8000/read_file?path={self.blobs[0][0]}/file.txt",
        )
        assert response.status_code == 200, response.content.decode()
        assert response.content.decode() == self.test_file_content, response.content.decode()

    def test_write_rw_encfs(self):

        test_content = "Hello, EncFS!"
        file_path = f"{self.blobs[0][0]}/new_file.txt"
        response = requests.post(
            f"http://{self.encfs_ip}:8000/write_file?path={file_path}",
            test_content,
        )
        assert response.status_code == 200, response.content.decode()
        assert response.content.decode() == f"{file_path} written to", response.content.decode()

    def test_read_ro_encfs(self):

        response = requests.get(
            f"http://{self.encfs_ip}:8000/read_file?path={self.blobs[1][0]}/file.txt",
        )
        assert response.status_code == 200, response.content.decode()
        assert response.content.decode() == self.test_file_content, response.content.decode()

    def test_write_ro_encfs(self):

        test_content = "Hello, EncFS!"
        file_path = f"{self.blobs[1][0]}/new_file.txt"
        response = requests.post(
            f"http://{self.encfs_ip}:8000/write_file?path={file_path}",
            test_content,
        )
        assert response.status_code == 500, response.content.decode()
        assert response.content == b"Read-only file system", response.content.decode()


if __name__ == "__main__":
    unittest.main()
