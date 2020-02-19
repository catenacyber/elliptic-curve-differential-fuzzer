// Copyright (c) 2020 Catena cyber
// Author Philippe Antoine <p.antoine@catenacyber.fr>


#include "../fuzz_ec.h"
#include "../goelliptic.h"
#include <stdlib.h>
#include <stdio.h>

void fuzzec_golang_process(fuzzec_input_t * input, fuzzec_output_t * output) {
    size_t clen = ECDF_BYTECEIL(input->groupBitLen);
    GoSlice px = {(void *) input->coordx, clen, clen};
    GoSlice py = {(void *) input->coordy, clen, clen};
    GoSlice sc = {(void *) input->bignum, clen, clen};
    GoSlice out = {output->points[0], 1 + 2 * clen, 1 + 2 * clen};

    int r = GoProcess(input->tls_id, px, py, sc, out);
    if (output->points[0][0] == 0) {
        output->pointSizes[0] = 1;
    } else {
        output->pointSizes[0] = 1 + 2 * clen;
    }
#ifdef DEBUG
    printf("golang:");
    for (size_t j=0; j<FUZZEC_NBPOINTS; j++) {
        for (size_t i=0; i<output->pointSizes[j]; i++) {
            printf("%02x", output->points[j][i]);
        }
        printf("\n");
    }
#endif
    output->errorCode = r;
}

void fuzzec_golang_add(fuzzec_input_t * input, fuzzec_output_t * output) {
    size_t clen = ECDF_BYTECEIL(input->groupBitLen);
    GoSlice px = {(void *) input->coordx, clen, clen};
    GoSlice py = {(void *) input->coordy, clen, clen};
    GoSlice qx = {(void *) input->coord2x, clen, clen};
    GoSlice qy = {(void *) input->coord2y, clen, clen};
    GoSlice out = {output->points[0], 1 + 2 * clen, 1 + 2 * clen};

    int r = GoAdd(input->tls_id, px, py, qx, qy, out);
    if (output->points[0][0] == 0) {
        output->pointSizes[0] = 1;
    } else {
        output->pointSizes[0] = 1 + 2 * clen;
    }
    output->errorCode = r;
#ifdef DEBUG
    if (output->errorCode != FUZZEC_ERROR_NONE) {
        return;
    }
    printf("golang: ");
    for (size_t j=0; j<FUZZEC_NBPOINTS; j++) {
        for (size_t i=0; i<output->pointSizes[j]; i++) {
            printf("%02x", output->points[j][i]);
        }
        printf("\n");
    }
#endif
}
