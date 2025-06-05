# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

import base64
import json
import re
import struct

from typing import Tuple
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA384
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from OpenSSL import crypto

# Data structures are based on SEV-SNP Firmware ABI Specification
# https://www.amd.com/en/support/tech-docs/sev-secure-nested-paging-firmware-abi-specification

# Report Data
REPORT_DATA_SIZE = 64

# SNP Report (Table 21)
SNP_REPORT_STRUCTURE = "".join(
    [
        "I",  # Version
        "I",  # Guest SVN
        "Q",  # Policy
        "16s",  # Family ID
        "16s",  # Image ID
        "I",  # VMPL
        "I",  # Signature Algorithm
        "Q",  # Current TCB
        "Q",  # Platform Info
        "I",  # Signing Key/Mask Chip Key/Author Key
        "4x",  # -----
        f"{REPORT_DATA_SIZE}s",  # Report Data
        "48s",  # Measurement
        "32s",  # Host Data
        "48s",  # ID Key Digest
        "48s",  # Author Key Digest
        "32s",  # Report ID
        "32s",  # Report ID MAA
        "Q",  # Reported TCB
        "24x",  # -----
        "64s",  # Chip ID
        "Q",  # Committed TCB
        "B",  # Current Build
        "B",  # Current Minor
        "B",  # Current Major
        "x",  # -----
        "B",  # Committed Build
        "B",  # Committed Minor
        "B",  # Committed Major
        "x",  # -----
        "Q",  # Launch TCB
        "168x",  # -----
        "512s",  # Signature
    ]
)
SNP_REPORT_SIZE = struct.calcsize(SNP_REPORT_STRUCTURE)

SIGNATURE_STRUCTURE = "".join(
    [
        "72s",  # R Component
        "72s",  # S Component
        "368x",  # -----
    ]
)

# Hardcode the AMD root of trust public key, so that locally obtained
# certificate chain used to sign the report can be traced to a known good value.
AMD_ROOT_PUBLIC_KEY = load_pem_public_key(
    """-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0Ld52RJOdeiJlqK2JdsV
mD7FktuotWwX1fNgW41XY9Xz1HEhSUmhLz9Cu9DHRlvgJSNxbeYYsnJfvyjx1MfU
0V5tkKiU1EesNFta1kTA0szNisdYc9isqk7mXT5+KfGRbfc4V/9zRIcE8jlHN61S
1ju8X93+6dxDUrG2SzxqJ4BhqyYmUDruPXJSX4vUc01P7j98MpqOS95rORdGHeI5
2Naz5m2B+O+vjsC060d37jY9LFeuOP4Meri8qgfi2S5kKqg/aF6aPtuAZQVR7u3K
FYXP59XmJgtcog05gmI0T/OitLhuzVvpZcLph0odh/1IPXqx3+MnjD97A7fXpqGd
/y8KxX7jksTEzAOgbKAeam3lm+3yKIcTYMlsRMXPcjNbIvmsBykD//xSniusuHBk
gnlENEWx1UcbQQrs+gVDkuVPhsnzIRNgYvM48Y+7LGiJYnrmE8xcrexekBxrva2V
9TJQqnN3Q53kt5viQi3+gCfmkwC0F0tirIZbLkXPrPwzZ0M9eNxhIySb2npJfgnq
z55I0u33wh4r0ZNQeTGfw03MBUtyuzGesGkcw+loqMaq1qR4tjGbPYxCvpCq7+Og
pCCoMNit2uLo9M18fHz10lOMT8nWAUvRZFzteXCm+7PHdYPlmQwUw3LvenJ/ILXo
QPHfbkH0CyPfhl1jWhJFZasCAwEAAQ==
-----END PUBLIC KEY-----
""".encode(),
)

_TRAILER = b"\xA3\x03\x02\x01\x01"          # [3] IMPLICIT INTEGER 1

def _fix_trailer_fields(der: bytes) -> bytes:
    """
    Remove *all* trailerField TLVs and fix the two surrounding SEQUENCE
    length bytes for each occurrence.
    """
    buf = bytearray(der)
    verbose = True
    cursor = 0

    while True:
        idx = buf.find(_TRAILER, cursor)
        if idx == -1:
            break

        # Walk backwards to find the inner and outer SEQUENCE tags.
        inner = buf.rfind(b"\x30", 0, idx)        # params SEQUENCE
        outer = buf.rfind(b"\x30", 0, inner)      # AlgorithmIdentifier SEQUENCE
        if inner == -1 or outer == -1:
            raise ValueError("Could not locate enclosing SEQUENCEs")

        if verbose:
            print(f"[attestation] strip trailerField at 0x{idx:X}, "
                  f"adjust len @inner 0x{inner+1:X} & outer 0x{outer+1:X}")

        buf[inner + 1] -= 5      # inner length
        buf[outer + 1] -= 5      # outer length
        del buf[idx : idx + 5]   # remove trailerField

        cursor = idx             # continue search after this position

    return bytes(buf)


def _pem_to_der(pem: bytes) -> bytes:
    body = b"".join(line.strip() for line in pem.splitlines()
                    if not line.startswith(b"-----"))
    return base64.b64decode(body)


def _load_cert_lenient(pem_bytes: bytes) -> x509.Certificate:
    """
    1. Fast path: strict loader (RFC-compliant certs).
    2. If EncodedDefault, run patcher -> strict DER loader.
    3. If anything *else* bombs, fall back to OpenSSL.
    """
    try:
        return x509.load_pem_x509_certificate(pem_bytes)          # ①
    except ValueError as err:
        if "EncodedDefault" not in str(err):
            raise

    fixed_der = _fix_trailer_fields(_pem_to_der(pem_bytes))       # ②
    try:
        return x509.load_der_x509_certificate(fixed_der)
    except ValueError:
        pass                                                     # rare

    # ③ last-chance – OpenSSL parse -> patch -> strict
    openssl_x509 = crypto.load_certificate(crypto.FILETYPE_PEM, pem_bytes)
    der = crypto.dump_certificate(crypto.FILETYPE_ASN1, openssl_x509)
    fixed_der = _fix_trailer_fields(der)
    return x509.load_der_x509_certificate(fixed_der)

def get_certificate_chain(certificate_chain: bytes) -> Tuple[x509.Certificate, ...]:
    chain_json = json.loads(base64.b64decode(certificate_chain).decode())
    print("[attestation] decoded certificate JSON:\n" + json.dumps(chain_json, indent=2, sort_keys=True))

    pem_blobs = [
        chain_json["vcekCert"],
        *re.findall(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            chain_json["certificateChain"],
            flags=re.DOTALL,
        ),
    ]

    return tuple(_load_cert_lenient(pem.encode()) for pem in pem_blobs)


def cert_signed_other_cert(
    parent_cert: x509.Certificate,
    child_cert: x509.Certificate,
) -> bool:
    try:
        parent_cert.public_key().verify(  # type: ignore
            child_cert.signature,
            child_cert.tbs_certificate_bytes,
            PSS(
                mgf=MGF1(SHA384()),
                salt_length=SHA384.digest_size,  # type: ignore
            ),  # type: ignore
            SHA384(),  # type: ignore
        )
        return True

    except InvalidSignature:
        return False


def validate_attestation(
    attestation_bytes: bytes,
    certificate_chain: bytes,
    expected_report_data: str,
) -> bool:
    (
        version,
        guest_svn,
        policy,
        family_id,
        image_id,
        vmpl,
        signature_algorithm,
        current_tcb,
        platform_info,
        author_key,
        report_data,
        measurement,
        host_data,
        id_key_digest,
        author_key_digest,
        report_id,
        report_id_ma,
        reported_tcb,
        chip_id,
        committed_tcb,
        current_build,
        current_minor,
        current_major,
        committed_build,
        committed_minor,
        committed_major,
        launch_tcb,
        signature,
    ) = struct.unpack_from(f"<{SNP_REPORT_STRUCTURE}", attestation_bytes, 0)

    # Validate report was generated based on the provided report data
    # (i.e. This is the report we requested)
    seen_report_data = report_data.rstrip(b"\x00").decode()
    print(f"Checking that report data in the attestation: {seen_report_data}")
    print(f"Matches the report data we provided: {expected_report_data}")
    assert seen_report_data == expected_report_data
    print(f"Success")

    # Get the certificate chain to validate that the report is ultimately
    # endorsed by a trusted AMD certificate
    vcek_cert, ark_cert, root_cert = get_certificate_chain(certificate_chain)

    # Validate the VCEK certificate signed the report
    print("Verifying that the VCEK certificate signed the report")
    vcek_cert.public_key().verify(  # type: ignore
        encode_dss_signature(
            *(
                int.from_bytes(n, byteorder="little")
                for n in struct.unpack_from(SIGNATURE_STRUCTURE, signature)
            )
        ),
        attestation_bytes[: -len(signature)],
        ECDSA(SHA384()),  # type: ignore
    )  # type: ignore
    print("Success")

    print("Verifying that the ARK certificate signed the VCEK certificate")
    assert cert_signed_other_cert(ark_cert, vcek_cert)
    print("Success")

    print("Verifying that the Root certificate signed the ARK certificate")
    assert cert_signed_other_cert(root_cert, ark_cert)
    print("Success")

    print("Validate the AMD root certificate matches the known good value")
    assert (
        root_cert.public_key().public_numbers()  # type: ignore
        == AMD_ROOT_PUBLIC_KEY.public_numbers()  # type: ignore
    )
    print("Success")

    print("All validation passed successfully")