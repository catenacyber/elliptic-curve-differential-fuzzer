// Copyright (c) 2020 Catena cyber
// Author Philippe Antoine <p.antoine@catenacyber.fr>


#include "../fuzz_ec.h"
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

static const char * nameOfCurve(uint16_t tlsid) {
    switch (tlsid) {
        case 19:
            return "p192";
        case 21:
            return "p224";
        case 22:
            return "secp256k1";
        case 23:
            return "p256";
        case 24:
            return "p384";
        case 25:
            return "p521";
    }
    return NULL;
}

void fuzzec_js_process(fuzzec_input_t * input, fuzzec_output_t * output) {
    char result[2048];
    char cmd[2048];
    const char *curve = nameOfCurve(input->tls_id);
    if (curve == NULL) {
        output->errorCode = FUZZEC_ERROR_UNSUPPORTED;
        return;
    }
    int offset = snprintf(cmd, 2048, "node elliptic.js %s ", curve);
    //dangerous overflow
    for (size_t i=0; i<2*input->coordSize+1; i++) {
        offset += snprintf(cmd+offset, 2048-offset, "%02x", input->coord[i]);
    }
    cmd[offset] = ' ';
    offset++;
    for (size_t i=0; i<input->coordSize; i++) {
        offset += snprintf(cmd+offset, 2048-offset, "%02x", input->bignum[i]);
    }
    printf("lolexec %s\n", cmd);
    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        printf("popen failed\n");
        output->errorCode = FUZZEC_ERROR_UNKNOWN;
        return;
    }

    if (fgets(result, sizeof(result), fp) == NULL) {
        output->errorCode = FUZZEC_ERROR_UNKNOWN;
        printf("fgets failed\n");
        pclose(fp);
        return;
    }
    /* close */
    pclose(fp);
    result[2047] = 0;

    // hexdecode
    output->pointSizes[0] = strlen(result)/2;
    //printf("lolres %s\n", result);
    for (size_t i=0; i<output->pointSizes[0]; i++) {
        if (!isxdigit(result[2*i]) || !isxdigit(result[2*i+1])) {
            //invalid hexadecimal
            output->errorCode = FUZZEC_ERROR_UNKNOWN;
            return;
        }
        output->points[0][i] = (result[2*i] >= 'A' ? ((result[2*i] & 0xdf) - 'A') + 10 : (result[2*i] - '0')) << 4;
        output->points[0][i] |= (result[2*i+1] >= 'A' ? ((result[2*i+1] & 0xdf) - 'A') + 10 : (result[2*i+1] - '0'));
    }
#ifdef DEBUG
    printf("nodejs/elliptic:");
    for (size_t j=0; j<FUZZEC_NBPOINTS; j++) {
        for (size_t i=0; i<output->pointSizes[j]; i++) {
            printf("%02x", output->points[j][i]);
        }
        printf("\n");
    }
#endif
    output->errorCode = FUZZEC_ERROR_NONE;
}

//TODO void fuzzec_js_add(fuzzec_input_t * input, fuzzec_output_t * output) {
