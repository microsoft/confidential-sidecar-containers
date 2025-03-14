/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#pragma once

#include <sys/types.h>
#include <stdint.h>

/* structures common to both 5.15.* and 6.* kernels */
/* essentially this is the interface to the PSP */

/* from SEV-SNP Firmware ABI Specification Table 20 */
typedef struct {
    uint8_t report_data[64];
    uint32_t vmpl;
    uint8_t reserved[28]; // needs to be zero
} msg_report_req;

/* from SEV-SNP Firmware ABI Specification from Table 23 */

// clang-format off
typedef struct {
    uint32_t    version;                // Version number of this attestation report. Set to 3 for the current (March 2025) specification.
    uint32_t    guest_svn;              // The guest SVN
    uint64_t    policy;                 // see table 10 - various settings
    __uint128_t family_id;              // The family ID provided at launch.
    __uint128_t image_id;               // The image ID provided at launch.
    uint32_t    vmpl;                   // the request VMPL for the attestation report
    uint32_t    signature_algo;         // The signature algorithm used to sign this report. See Chapter 10 for encodings.
    uint8_t     current_tcb[8];         // CurrentTcb (was platform_version)
    uint64_t    platform_info;          // information about the platform see table 24
    uint32_t    author_key_en;          // The structure starting 48h
                                        // Note: the order of C bitfields can't be relied on.  Hence this structure have to be an uint32_t.
    uint32_t    reserved1;              // must be zero
    uint8_t     report_data[64];        // Guest provided data.
    uint8_t     measurement[48];        // measurement calculated at launch
    uint8_t     host_data[32];          // data provided by the hypervisor at launch
    uint8_t     id_key_digest[48];      // SHA-384 digest of the ID public key that signed the ID block provided in SNP_LAUNCH_FINISH
    uint8_t     author_key_digest[48];  // SHA-384 digest of the Author public key that certified the ID key, if provided in SNP_LAUNCH_FINISH. Zeros if author_key_en is 1 (sounds backwards to me).
    uint8_t     report_id[32];          // Report ID of this guest.
    uint8_t     report_id_ma[32];       // Report ID of this guest's mmigration agent.
    uint8_t     reported_tcb[8];        // Reported TCB version used to derive the VCEK that signed this report
    uint8_t     cpuid_fam_id;           // Family ID (Combined Extended Family ID and Family ID)
    uint8_t     cpuid_mod_id;           // Model (combined Extended Model and Model fields)
    uint8_t     cpuid_step;             // Stepping
    uint8_t     reserved2[21];          // reserved
    uint8_t     chip_id[64];            // Identifier unique to the chip
    uint8_t     committed_tcb[8];       // CommittedTcb (was committed_svn)
    uint8_t     current_build;          // The build number of CurrentVersion.
    uint8_t     current_minor;          // The minor number of CurrentVersion.
    uint8_t     current_major;          // The major number of CurrentVersion.
    uint8_t     reserved3;              // reserved
    uint8_t     committed_build;        // The build number of CommittedVersion.
    uint8_t     committed_minor;        // The minor number of CommittedVersion.
    uint8_t     committed_major;        // The major number of CommittedVersion.
    uint8_t     reserved4;              // reserved
    uint8_t     launch_tcb[8];          // The CurrentTcb at the time the guest was launched or imported. (was launch_svn)
    uint8_t     reserved5[168];         // reserved
    uint8_t     signature[512];         // Signature of this attestation report. See table 23.
} snp_attestation_report;
// clang-format on

/* from SEV-SNP Firmware ABI Specification Table 22 */
typedef struct {
    uint32_t status;
    uint32_t report_size;
    uint8_t reserved[24];
    snp_attestation_report report;
    uint8_t padding[64]; // padding to the size of SEV_SNP_REPORT_RSP_BUF_SZ (i.e., 1280 bytes)
} msg_response_resp;
