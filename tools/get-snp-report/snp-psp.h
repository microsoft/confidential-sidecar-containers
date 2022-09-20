/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#include <sys/ioctl.h>
#include <sys/types.h>
#include <stdint.h>

/* From sev-snp driver include/uapi/linux/psp-sev-guest.h */
struct sev_snp_guest_request {
	uint8_t req_msg_type;
	uint8_t rsp_msg_type;
	uint8_t msg_version;
	uint16_t request_len;
	uint64_t request_uaddr;
	uint16_t response_len;
	uint64_t response_uaddr;
	uint32_t error;		/* firmware error code on failure (see psp-sev.h) */
};

enum snp_msg_type {
	SNP_MSG_TYPE_INVALID = 0,
	SNP_MSG_CPUID_REQ,
	SNP_MSG_CPUID_RSP,
	SNP_MSG_KEY_REQ,
	SNP_MSG_KEY_RSP,
	SNP_MSG_REPORT_REQ,
	SNP_MSG_REPORT_RSP,
	SNP_MSG_EXPORT_REQ,
	SNP_MSG_EXPORT_RSP,
	SNP_MSG_IMPORT_REQ,
	SNP_MSG_IMPORT_RSP,
	SNP_MSG_ABSORB_REQ,
	SNP_MSG_ABSORB_RSP,
	SNP_MSG_VMRK_REQ,
	SNP_MSG_VMRK_RSP,
	SNP_MSG_TYPE_MAX
};

/* from SEV-SNP Firmware ABI Specification Table 20 */
typedef struct {
    uint8_t report_data[64];
    uint32_t vmpl;
    uint8_t reserved[28]; // needs to be zero
} msg_report_req;

/* from SEV-SNP Firmware ABI Specification from Table 21 */
typedef struct {
    uint32_t    version;                // version no. of this attestation report. Set to 1 for this specification.
    uint32_t    guest_svn;              // The guest SVN
    uint64_t    policy;                 // see table 8 - various settings
    __uint128_t family_id;              // as provided at launch
    __uint128_t image_id;               // as provided at launch
    uint32_t    vmpl;                   // the request VMPL for the attestation report
    uint32_t    signature_algo;
    uint64_t    platform_version;       // The install version of the firmware
    uint64_t    platform_info;          // information about the platform see table 22
                                        // not going to try to use bit fields for this next one. Too confusing as to which bit of the byte will be used. Make a mask if you need it
    uint32_t    author_key_en;          // 31 bits of reserved, must be zero, bottom bit indicates that the digest of the
                                        // author key is present in AUTHOR_KEY_DIGEST. Set to the value of GCTX.AuthorKeyEn.
    uint32_t    reserved1;              // must be zero
    uint8_t     report_data[64];        // Guest provided data.
    uint8_t     measurement[48];        // measurement calculated at launch
    uint8_t     host_data[32];          // data provided by the hypervisor at launch
    uint8_t     id_key_digest[48];      // SHA-384 digest of the ID public key that signed the ID block provided in SNP_LAUNCH_FINISH
    uint8_t     author_key_digest[48];  // SHA-384 digest of the Author public key that certified the ID key, if provided in SNP_LAUNCH_FINISH. Zeros if author_key_en is 1 (sounds backwards to me).
    uint8_t     report_id[32];          // Report ID of this guest.
    uint8_t     report_id_ma[32];       // Report ID of this guest's mmigration agent.
    uint64_t    reported_tcb;           // Reported TCB version used to derive the VCEK that signed this report
    uint8_t     reserved2[24];          // reserved
    uint8_t     chip_id[64];        // Identifier unique to the chip
    uint8_t     committed_svn[8];   // The current commited SVN of the firware (version 2 report feature)
    uint8_t     committed_version[8];   // The current commited version of the firware
    uint8_t     launch_svn[8];      // The SVN that this guest was launched or migrated at
    uint8_t     reserved3[168];         // reserved
    uint8_t     signature[512];         // Signature of this attestation report. See table 23.
} snp_attestation_report;

/* from SEV-SNP Firmware ABI Specification Table 22 */
typedef struct {
    uint32_t status;
    uint32_t report_size;
    uint8_t reserved[24];    
    snp_attestation_report report;
    uint8_t padding[64]; // padding to the size of SEV_SNP_REPORT_RSP_BUF_SZ (i.e., 1280 bytes)
} msg_response_resp;

#define SEV_GUEST_IOC_TYPE		'S'
#define SEV_SNP_GUEST_MSG_REQUEST	_IOWR(SEV_GUEST_IOC_TYPE, 0x0, struct sev_snp_guest_request)
#define SEV_SNP_GUEST_MSG_REPORT	_IOWR(SEV_GUEST_IOC_TYPE, 0x1, struct sev_snp_guest_request)
#define SEV_SNP_GUEST_MSG_KEY		_IOWR(SEV_GUEST_IOC_TYPE, 0x2, struct sev_snp_guest_request)
