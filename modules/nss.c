// Copyright (c) 2018 Catena cyber
// Author Philippe Antoine <p.antoine@catenacyber.fr>


#include "../fuzz_ec.h"
#define MP_IOFUNC 1
#include "mpi.h"
#include "ecl.h"

#define BYTECEIL(numbits) (((numbits) + 7) >> 3)

static int eccurvetypeFromTlsId(uint16_t tlsid) {
    switch (tlsid) {
        case 19:
            return ECCurve_NIST_P192;
        case 21:
            return ECCurve_NIST_P224;
        case 23:
            return ECCurve_NIST_P256;
        case 24:
            return ECCurve_NIST_P384;
        case 25:
            return ECCurve_NIST_P521;
    }
    return 0;
}


void fuzzec_nss_process(fuzzec_input_t * input, fuzzec_output_t * output) {
    mp_err err;
    mp_int scalar1;
    mp_int scalar2;
    mp_int point1x;
    mp_int point1y;

    //initialize
    ECGroup *mcurve = ECGroup_fromName(CURVEID_NSS);
    if (mcurve == NULL) {
        output->errorCode = FUZZEC_ERROR_UNSUPPORTED;
        return;
    }

    mp_init(&scalar1);
    mp_init(&scalar2);
    mp_init(&point1x);
    mp_init(&point1y);
    err = mp_read_raw(&scalar1, input->bignum1, input->bignum1Size);
    if (err) {
        output->errorCode = FUZZEC_ERROR_UNKNOWN;
        goto end;
    }
    err = mp_read_raw(&scalar2, input->bignum2, input->bignum2Size);
    if (err) {
        output->errorCode = FUZZEC_ERROR_UNKNOWN;
        goto end;
    }

    //elliptic curve computations
    //P1=scalar1*G
    err = ECPoints_mul(mcurve, &scalar1, NULL, NULL, NULL, &point1x, &point1y);
    if (err) {
        output->errorCode = FUZZEC_ERROR_UNKNOWN;
        return;
    }
    //TODO P2=scalar2*P1 (=scalar2*scalar1*G)
    //P3=P1+P2

    //format output
    if (mp_raw_size(&point1x) == 0 && mp_raw_size(&point1y) == 0) {
        output->pointSizes[0] = 1;
        output->points[0][0] = 0;
    } else {
        output->pointSizes[0] = 1 + 2*BYTECEIL(input->groupBitLen);
        mp_toraw(&point1x, output->points[0]+1);
        mp_toraw(&point1y, output->points[0]+1+BYTECEIL(input->groupBitLen));
    }
    //TODO

#ifdef DEBUG
    printf("nss:");
    for (size_t j=0; j<FUZZEC_NBPOINTS; j++) {
        for (size_t i=0; i<output->pointSizes[j]; i++) {
            printf("%02x", output->points[j][i]);
        }
        printf("\n");
    }
#endif
    output->errorCode = FUZZEC_ERROR_NONE;

end:
    mp_clear(&scalar1);
    mp_clear(&scalar2);
    mp_clear(&point1x);
    mp_clear(&point1y);
    ECGroup_free(mcurve);
    return;
}
