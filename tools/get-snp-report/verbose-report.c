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

#include "snp-attestation.h"
#include "fetch5.h"
#include "fetch6.h"

#include "helpers.h"

// Main expects the hex string representation of the report data as the only argument
// Prints the raw binary format of the report so it can be consumed by the tools under
// the directory internal/guest/attestation

int main(int argc, char *argv[])
{    
    bool success = false;
    uint8_t *snp_report_hex;
    const char *report_data_hexstring = "";

    if (argc > 1) {
        report_data_hexstring = argv[1];
    }

    if (supportsDevSev()) {
        success = fetchAttestationReport5(report_data_hexstring, (void*) &snp_report_hex);
    } else if (supportsDevSevGuest()) {
        success = fetchAttestationReport6(report_data_hexstring, (void*) &snp_report_hex);
    } else {
        fprintf(stderr, "No supported SNP device found\n");
    }
   
    if (success) {
        printReport((const snp_attestation_report *)snp_report_hex);
        exit(0);
    }
    return 1;
}
