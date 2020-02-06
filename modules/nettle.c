// Copyright (c) 2018 Catena cyber
// Author Philippe Antoine <p.antoine@catenacyber.fr>


#include "../fuzz_ec.h"
#include <stdio.h>
#include <nettle/ecc.h>
#include <nettle/ecc-curve.h>
#include <stdlib.h>

static const struct ecc_curve * tls1_group_id_lookup(uint16_t tlsid) {
    switch (tlsid) {
        case 19:
            return nettle_get_secp_192r1();
        case 21:
            return nettle_get_secp_224r1();
        case 23:
            return nettle_get_secp_256r1();
        case 24:
            return nettle_get_secp_384r1();
        case 25:
            return nettle_get_secp_521r1();
    }
    return NULL;
}

void fuzzec_nettle_process(fuzzec_input_t * input, fuzzec_output_t * output) {
    mpz_t scalar1;
    mpz_t scalar2;
    struct ecc_scalar ecscalar1;
    struct ecc_point point1;
    struct ecc_point point2;
    const struct ecc_curve * curve;

    //initialize
    curve = tls1_group_id_lookup(input->tls_id);
    if (curve == NULL) {
        output->errorCode = FUZZEC_ERROR_UNSUPPORTED;
        return;
    }

    nettle_mpz_init_set_str_256_u(scalar1, input->coordSize, input->coordx);
    nettle_mpz_init_set_str_256_u(scalar2, input->coordSize, input->coordy);
    ecc_scalar_init(&ecscalar1, curve);
    ecc_point_init(&point1, curve);
    ecc_point_init(&point2, curve);

    if (ecc_point_set (&point1, scalar1, scalar2) == 0) {
        output->errorCode = FUZZEC_ERROR_UNKNOWN;
        goto end;
    }
    nettle_mpz_set_str_256_u(scalar1, input->bignumSize, input->bignum);
    if (ecc_scalar_set (&ecscalar1, scalar1) == 0) {
        // above field prime
        output->errorCode = FUZZEC_ERROR_UNSUPPORTED;
        goto end;
    }

    //elliptic curve computations
    //P2=scalar1*P1
    ecc_point_mul(&point2, &ecscalar1, &point1);

    //format output
    //TODO test null output
    ecc_point_get(&point2, scalar1, scalar2);
    output->pointSizes[0] = 1 + 2*input->coordSize;
    //uncompressed form
    output->points[0][0] = 4;
    nettle_mpz_get_str_256(input->coordSize, output->points[0]+1, scalar1);
    nettle_mpz_get_str_256(input->coordSize, output->points[0]+1+input->coordSize, scalar2);
    ecc_point_get(&point2, scalar1, scalar2);

#ifdef DEBUG
    printf("nettle:");
    for (size_t j=0; j<FUZZEC_NBPOINTS; j++) {
        for (size_t i=0; i<output->pointSizes[j]; i++) {
            printf("%02x", output->points[j][i]);
        }
        printf("\n");
    }
#endif
    output->errorCode = FUZZEC_ERROR_NONE;

end:
    mpz_clears(scalar1, scalar2, NULL);
    ecc_scalar_clear(&ecscalar1);
    ecc_point_clear(&point1);
    ecc_point_clear(&point2);
    return;
}
