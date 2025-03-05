#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

#include "snp-ioctl5.h"

#include "helpers.h"



// Helper functions
uint8_t* decodeHexString(const char *hexstring, size_t padTo) // will zero pad to bufferLen
{
    size_t len = strlen(hexstring);
    size_t out_len = len/2+1;
    if (out_len < padTo)
        out_len = padTo;
    uint8_t *byte_array = (uint8_t*) malloc(out_len);
    memset(byte_array, 0, out_len);

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
    fprintf(stdout, "  %s: ", desc);
    /* Pad it so that we have 24 characters before the hex */
    int padding = 20 - strlen(desc);
    if (padding < 0)
        padding = 0;
    for (int count = 0; count < padding; count++)
        putchar(' ');

    for (size_t pos = 0; pos < len; pos++) {
        fprintf(stdout, "%02x", data[swap ? len - pos - 1 : pos]);
        if (pos % 32 == 31 && pos != len - 1)
            printf("\n                        ");
        else if (pos % 16 == 15 && pos != len - 1)
            putchar(' ');
    }
    fprintf(stdout, "\n");
}

void printReport(const snp_attestation_report *r)
{
    /*
     * PRINT_VAL is intended to interpert the number in little endian and print
     * the hex representation of it.  This should be used for bitfields as well
     * as the spec orders the bits from most significant to least significant in
     * the presented table (and when it says, for example, bits 63:6 are
     * reserved, it means that val>>6 == 0).
     */
    PRINT_VAL(r, version);
    PRINT_VAL(r, guest_svn);
    PRINT_VAL(r, policy);
    PRINT_VAL(r, family_id);
    PRINT_VAL(r, image_id);
    PRINT_VAL(r, vmpl);
    PRINT_VAL(r, signature_algo);
    PRINT_VAL(r, current_tcb);
    PRINT_VAL(r, platform_info);
    PRINT_VAL(r, author_key_en);
    PRINT_BYTES(r, reserved1);
    PRINT_BYTES(r, report_data);
    PRINT_BYTES(r, measurement);
    PRINT_BYTES(r, host_data);
    PRINT_BYTES(r, id_key_digest);
    PRINT_BYTES(r, author_key_digest);
    PRINT_BYTES(r, report_id);
    PRINT_BYTES(r, report_id_ma);
    PRINT_VAL(r, reported_tcb);
    PRINT_VAL(r, cpuid_fam_id);
    PRINT_VAL(r, cpuid_mod_id);
    PRINT_VAL(r, cpuid_step);
    PRINT_BYTES(r, reserved2);
    PRINT_BYTES(r, chip_id);
    PRINT_VAL(r, committed_tcb);
    PRINT_VAL(r, current_build);
    PRINT_VAL(r, current_minor);
    PRINT_VAL(r, current_major);
    PRINT_BYTES(r, reserved3);
    PRINT_VAL(r, committed_build);
    PRINT_VAL(r, committed_minor);
    PRINT_VAL(r, committed_major);
    PRINT_BYTES(r, reserved4);
    PRINT_VAL(r, launch_tcb);
    PRINT_BYTES(r, reserved5);
    PRINT_BYTES(r, signature);
}
