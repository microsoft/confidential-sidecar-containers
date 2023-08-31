#include <stdio.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/types.h>

typedef struct {
/* response data, see SEV-SNP spec for the format */
    uint8_t  data[4000];
} snp_report_resp;

// aka/replaced by this from include/uapi/linux/sev-guest.h
//
typedef struct {
    /* message version number (must be non-zero) */
    uint8_t msg_version;

    /* Request and response structure address */
    uint64_t req_data;
    uint64_t resp_data;

    /* firmware error code on failure (see psp-sev.h) */
    uint64_t fw_err;
} snp_guest_request_ioctl;

#define SNP_GUEST_REQ_IOC_TYPE        'S'
#define SNP_GET_REPORT                _IOWR(SNP_GUEST_REQ_IOC_TYPE, 0x0, snp_guest_request_ioctl)

int main () {
    printf("size of snp_report_resp: %zu\n", sizeof(snp_report_resp));
    printf("size of snp_guest_request_ioctl: %zu\n", sizeof(snp_guest_request_ioctl));
    snp_guest_request_ioctl ioctl_req;
    printf("req_data's offset: %lu\n", (uint64_t)&ioctl_req.req_data - (uint64_t)&ioctl_req.msg_version);
    printf("SNP_GET_REPORT: %lu\n", SNP_GET_REPORT);
}