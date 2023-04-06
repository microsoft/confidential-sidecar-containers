
/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

#include "helpers.h"



int main(int argc, char** argv)
{
    char buffer[102400];
    int bytes_read = fread(buffer, 1, sizeof(buffer)-1, stdin);
    if (bytes_read < 0) {
        fprintf(stderr, "pipe read failed\n");
        exit(-1);
    }
    if (bytes_read == 0) {
        fprintf(stderr, "empty pipe\n");
        exit(-1);
    }
    if (bytes_read < sizeof(snp_attestation_report)) {
        fprintf(stderr, "pipe too short\n");
        exit(-1);
    }
    buffer[bytes_read] = 0;

    uint8_t* byte_array = decodeHexString(buffer, 0);
        
    printReport((const snp_attestation_report *)byte_array);

    return 0;
}