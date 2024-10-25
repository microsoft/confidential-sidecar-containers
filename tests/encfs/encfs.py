from contextlib import contextmanager
import subprocess
import tempfile
import hashlib


class CryptSetupFileSystem:
    DEVICE_NAME = "cryptdevice1"
    DEVICE_NAME_PATH = f"/dev/mapper/{DEVICE_NAME}"

    def _run_command(self, *args):
        subprocess.check_call(
            " ".join(
                [
                    "sudo cryptsetup --debug -v",
                    *args,
                ]
            ),
            shell=True,
        )

    def cleanup(self):
        if self._dir:
            subprocess.check_call(f"sudo umount {self._dir.name}", shell=True)
        if self.is_open:
            try:
                self._run_command("luksClose", self.DEVICE_NAME)
                self.is_open = False
            finally:
                self._dir.cleanup()

    def __init__(self, key_path, image_path):
        self.key_path = key_path
        self.image_path = image_path
        self.is_open = False
        with open(image_path, "wb") as f:
            f.seek(64 * 1024 * 1024 - 1)
            f.write(b"\0")

    def __enter__(self):
        try:
            print("Creating encrypted filesystem")
            # Format
            self._run_command(
                "luksFormat",
                "--type luks2",
                self.image_path,
                "--key-file",
                f'"{self.key_path}"',
                "--batch-mode",
                "--sector-size 4096",
                "--cipher aes-xts-plain64",
                "--pbkdf pbkdf2",
                "--pbkdf-force-iterations 1000",
            )
            print("decrypting")
            # Open
            self._run_command(
                "luksOpen",
                self.image_path,
                self.DEVICE_NAME,
                "--key-file",
                self.key_path,
                "--integrity-no-journal",
                "--persistent",
            )
            self.is_open = True
            print("Formatting")
            # Mount
            subprocess.check_call(f"sudo mkfs.ext4 {self.DEVICE_NAME_PATH}", shell=True)
            self._dir = tempfile.TemporaryDirectory()
            subprocess.check_call(
                f"sudo mount -t ext4 {self.DEVICE_NAME_PATH} {self._dir.name} -o loop",
                shell=True,
            )
            print("mounted successfully")
            return self._dir.name

        except Exception:
            self.cleanup()
            raise

    def __exit__(self, exc_type, exc_value, traceback):
        self.cleanup()

@contextmanager
def deploy_encfs(
    blob_name: str,
    blob_type: str,
    key: bytes,
    storage_account_name: str,
    container_name: str,
):
    def calculate_sha256(file_path):
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    with tempfile.TemporaryDirectory() as workspace:
        with tempfile.NamedTemporaryFile(dir=workspace, prefix="key_") as key_file, \
             tempfile.NamedTemporaryFile(dir=workspace, prefix="blob_") as blob_file:

            key_file.write(key)
            key_file.flush()

            with CryptSetupFileSystem(key_file.name, blob_file.name) as filesystem:
                yield filesystem

            # Calculate checksum before uploading
            local_checksum = calculate_sha256(blob_file.name)
            print(f"Local checksum (before upload): {local_checksum}")

            # Upload the blob
            subprocess.check_call([
                "az", "storage", "blob", "upload",
                "--account-name", storage_account_name,
                "--container-name", container_name,
                "--name", blob_name,
                "--file", blob_file.name,
                "--type", blob_type,
                "--auth-mode", "login",
                "--overwrite",
            ])
            print(f"Deployed blob {blob_name} into the storage container")

            # Download blob to temporary file for verification
            with tempfile.NamedTemporaryFile(dir=workspace, prefix="downloaded_blob_") as downloaded_blob:
                subprocess.check_call([
                    "az", "storage", "blob", "download",
                    "--account-name", storage_account_name,
                    "--container-name", container_name,
                    "--name", blob_name,
                    "--file", downloaded_blob.name,
                    "--auth-mode", "login"
                ])

                # Calculate checksum of downloaded blob
                downloaded_checksum = calculate_sha256(downloaded_blob.name)
                print(f"Downloaded blob checksum (after upload): {downloaded_checksum}")

                # Verify that the uploaded and downloaded checksums match
                if local_checksum != downloaded_checksum:
                    raise ValueError("Checksum mismatch: the uploaded blob does not match the local file.")
                else:
                    print("Checksum verification passed: the uploaded blob matches the local file.")
