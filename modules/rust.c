// Copyright (c) 2020 Catena cyber
// Author Philippe Antoine <p.antoine@catenacyber.fr>


#include "../fuzz_ec.h"
//#include "rust.h"
#include <stdlib.h>
#include <stdio.h>

int RustProcess(const uint8_t coordx[32], const uint8_t coordy[32], const uint8_t scalar[32], uint8_t result[65]);

void fuzzec_rust_process(fuzzec_input_t * input, fuzzec_output_t * output) {
    //secp256k1
    if (input->tls_id != 22) {
        output->errorCode = FUZZEC_ERROR_UNSUPPORTED;
        return;
    }
    size_t clen = ECDF_BYTECEIL(input->groupBitLen);
    output->errorCode = RustProcess(input->coordx, input->coordy, input->bignum, output->points[0]);
    if (output->points[0][0] == 0) {
        output->pointSizes[0] = 1;
    } else {
        output->pointSizes[0] = 2*clen+1;
    }
}

//TODO void fuzzec_rust_add(fuzzec_input_t * input, fuzzec_output_t * output) {
