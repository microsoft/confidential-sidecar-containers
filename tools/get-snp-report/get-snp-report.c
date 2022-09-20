/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

#include "snp-psp.h"

#define PRINT_VAL(ptr, field) printBytes(#field, (const uint8_t *)&(ptr->field), sizeof(ptr->field), true)
#define PRINT_BYTES(ptr, field) printBytes(#field, (const uint8_t *)&(ptr->field), sizeof(ptr->field), false)

// Helper functions
uint8_t* decodeHexString(char *hexstring)
{   
    size_t len = strlen(hexstring);
    uint8_t *byte_array = (uint8_t*) malloc(strlen(hexstring)*sizeof(uint8_t));
    
    for (size_t i = 0; i < len; i+=2) {        
        sscanf(hexstring, "%2hhx", &byte_array[i/2]);
        hexstring += 2;        
    }

    return byte_array;
}

char* encodeHexToString(uint8_t byte_array[], size_t len)
{    
    char* hexstring = (char*) malloc((2*len+1)*sizeof(char));

    for (size_t i = 0; i < len; i++)       
        sprintf(&hexstring[i*2], "%02x", byte_array[i]);                    
    
    hexstring[2*len] = '\0'; // string padding character    
    return hexstring;
}

void printBytes(const char *desc, const uint8_t *data, size_t len, bool swap)
{
    fprintf(stderr, "  %s: ", desc);
    int padding = 20 - strlen(desc);
    if (padding < 0)
        padding = 0;
    for (int count = 0; count < padding; count++)
        putchar(' ');

    for (size_t pos = 0; pos < len; pos++) {
        fprintf(stderr, "%02x", data[swap ? len - pos - 1 : pos]);
        if (pos % 32 == 31)
            printf("\n                        ");
        else if (pos % 16 == 15)
            putchar(' ');
    }
    fprintf(stderr, "\n");
}

void printReport(const snp_attestation_report *r)
{    
    PRINT_VAL(r, version);
    PRINT_VAL(r, guest_svn);
    PRINT_VAL(r, policy);
    PRINT_VAL(r, family_id);
    PRINT_VAL(r, image_id);
    PRINT_VAL(r, vmpl);
    PRINT_VAL(r, signature_algo);
    PRINT_BYTES(r, platform_version);
    PRINT_BYTES(r, platform_info);
    PRINT_VAL(r, author_key_en);
    PRINT_VAL(r, reserved1);
    PRINT_BYTES(r, report_data);
    PRINT_BYTES(r, measurement);
    PRINT_BYTES(r, host_data);
    PRINT_BYTES(r, id_key_digest);
    PRINT_BYTES(r, author_key_digest);
    PRINT_BYTES(r, report_id);
    PRINT_BYTES(r, report_id_ma);
    PRINT_VAL(r, reported_tcb);
    PRINT_BYTES(r, reserved2);
    PRINT_BYTES(r, chip_id);
    PRINT_BYTES(r, reserved3);
    PRINT_BYTES(r, signature);
}

bool fetchAttestationReport(char report_data_hexstring[], void **snp_report)
{
    msg_report_req msg_report_in;    
    msg_response_resp msg_report_out;
    
    int fd, rc;	
    
    struct sev_snp_guest_request payload = {
        .req_msg_type = SNP_MSG_REPORT_REQ,
        .rsp_msg_type = SNP_MSG_REPORT_RSP,
        .msg_version = 1,        
        .request_len = sizeof(msg_report_in),
        .request_uaddr = (uint64_t) (void*) &msg_report_in,
        .response_len = sizeof(msg_report_out),
        .response_uaddr = (uint64_t) (void*) &msg_report_out,
        .error = 0
    };
    
    memset((void*) &msg_report_in, 0, sizeof(msg_report_in));        
    memset((void*) &msg_report_out, 0, sizeof(msg_report_out));

    // MAA expects a SHA-256. So we use 32 bytes as size instead of msg_report_in.report_data
    // the report data is passed as a hexstring which needs to be decoded into an array of 
    // unsigned bytes
    uint8_t *reportData = decodeHexString(report_data_hexstring);   
    memcpy(msg_report_in.report_data, reportData, 32);

    // open the file descriptor of the PSP
    fd = open("/dev/sev", O_RDWR | O_CLOEXEC);

    if (fd < 0) {
        fprintf(stdout, "Failed to open /dev/sev\n");        
        return false;
    }

    // issue the custom SEV_SNP_GUEST_MSG_REPORT sys call to the sev driver
    rc = ioctl(fd, SEV_SNP_GUEST_MSG_REPORT, &payload);

    if (rc < 0) {
        fprintf(stdout, "Failed to issue ioctl SEV_SNP_GUEST_MSG_REPORT\n");        
        return false;    
    }

    #ifdef DEBUG_OUTPUT   
    fprintf(stderr, "Response header:\n");
    uint8_t *hdr = (uint8_t*) &msg_report_out;
    
    for (size_t i = 0; i < 32; i++) {
        fprintf(stderr, "%02x", hdr[i]);
        if (i % 16 == 15)
            fprintf(stderr, "\n");
        else
            fprintf(stderr, " ");
    }
    fprintf(stderr, "Attestation report:\n");
    printReport(&msg_report_out.report);
    #endif

    *snp_report = (snp_attestation_report *) malloc (sizeof(snp_attestation_report));        
    memcpy(*snp_report, &msg_report_out.report, sizeof(snp_attestation_report));

    return true;
}

// Main expects the hex string representation of the report data as the only argument
// Prints the raw binary format of the report so it can be consumed by the tools under
// the directory internal/guest/attestation
int main(int argc, char *argv[])
{    
    bool success;
    uint8_t *snp_report_hex;

    if (argc > 1) {        
        success = fetchAttestationReport(argv[1], (void*) &snp_report_hex);    
    } else {        
        success = fetchAttestationReport("", (void*) &snp_report_hex);    
    }
   
    if (success == true) {
        for (size_t i = 0; i < sizeof(snp_attestation_report); i++) {
            fprintf(stdout, "%02x", (uint8_t) snp_report_hex[i]);
        }

        return 0;
    }

    return -1;
}
