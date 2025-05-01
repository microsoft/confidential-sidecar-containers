This package implements the Attest operation to fetch an attestation token from MAA.
It interacts with the following Azure services:
- Microsoft Azure Attestation (maa): for issuing an attestation token given an attestation report signed by a key that is rooted to the cert chain and additional evidence including the blobs that have been hashed to the report's `HOST_DATA` and `REPORT_DATA` fields during virtual machine bringup and retrieval of the attestation report, respectively

The attestation report is fetched from the platform security processor by executing the <parent>/tools/get-snp-report tool which is compiled and copied into the container's root filesystem under /bin.

