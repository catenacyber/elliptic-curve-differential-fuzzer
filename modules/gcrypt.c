// Copyright (c) 2018 Catena cyber
// Author Philippe Antoine <p.antoine@catenacyber.fr>


#include "../fuzz_ec.h"
#include <gcrypt.h>

#define BYTECEIL(numbits) (((numbits) + 7) >> 3)

static const char * eccurvetypeFromTlsId(uint16_t tlsid) {
    switch (tlsid) {
        case 19:
            return "NIST P-192";
        case 21:
            return "NIST P-224";
        case 22:
            return "secp256k1";
        case 23:
            return "NIST P-256";
        case 24:
            return "NIST P-384";
        case 25:
            return "NIST P-521";
        case 26:
            return "brainpoolP256r1";
        case 27:
            return "brainpoolP384r1";
        case 28:
            return "brainpoolP512r1";
    }
    return "";
}

int fuzzec_gcrypt_init(){
    gpg_error_t err;
    err=gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    if (err)
        return 1;
    err=gcry_control(GCRYCTL_ENABLE_QUICK_RANDOM, 0);
    if (err)
        return 1;
    err=gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    if (err)
        return 1;
    return 0;
}

static void gcrypt_to_ecfuzzer(gcry_mpi_point_t pointZ, fuzzec_output_t * output, size_t index, size_t byteLen, gcry_ctx_t ctx) {
    gcry_mpi_t coordx;
    gcry_mpi_t coordy;
    gcry_mpi_t coordz;
    gpg_error_t err;

    coordx = gcry_mpi_new(0);
    coordy = gcry_mpi_new(0);

    if (gcry_mpi_ec_get_affine (coordx, coordy, pointZ, ctx)) {
        coordz = gcry_mpi_new(0);
        gcry_mpi_point_get(coordx, coordy, coordz, pointZ);
        if (gcry_mpi_get_nbits(coordz) == 0) {
            output->pointSizes[index] = 1;
            output->points[index][0] = 0;
        } else {
            output->errorCode = FUZZEC_ERROR_UNKNOWN;
            gcry_mpi_release(coordx);
            gcry_mpi_release(coordy);
            gcry_mpi_release(coordz);
            return;
        }
        gcry_mpi_release(coordz);
    } else {
        output->pointSizes[index] = 1 + 2 * byteLen;
        //uncompressed form
        output->points[index][0] = 4;

        err = gcry_mpi_print(GCRYMPI_FMT_USG, output->points[index]+1, byteLen, NULL, coordx);
        if (err) {
            output->errorCode = FUZZEC_ERROR_UNKNOWN;
            gcry_mpi_release(coordx);
            gcry_mpi_release(coordy);
            return;
        }
        err = gcry_mpi_print(GCRYMPI_FMT_USG, output->points[index]+1+byteLen, byteLen, NULL, coordy);
        if (err) {
            output->errorCode = FUZZEC_ERROR_UNKNOWN;
            gcry_mpi_release(coordx);
            gcry_mpi_release(coordy);
            return;
        }
    }
    gcry_mpi_release(coordx);
    gcry_mpi_release(coordy);
}

void fuzzec_gcrypt_process(fuzzec_input_t * input, fuzzec_output_t * output) {
    gpg_error_t err;
    gcry_ctx_t ctx;
    gcry_mpi_t scalar1;
    gcry_mpi_t scalar2;
    gcry_mpi_point_t pointG = NULL;
    gcry_mpi_point_t point1 = NULL;
    gcry_mpi_point_t point2 = NULL;
    gcry_mpi_point_t point3 = NULL;

    //initialize
    //TODO fuzz custom curves
    err = gcry_mpi_ec_new (&ctx, NULL, eccurvetypeFromTlsId(input->tls_id));
    if (err) {
        printf("fail %d\n", input->tls_id);
        output->errorCode = FUZZEC_ERROR_UNSUPPORTED;
        return;
    }

    err = gcry_mpi_scan(&scalar1, GCRYMPI_FMT_USG, input->bignum1, input->bignum1Size, NULL);
    if (err) {
        printf("fail2 %x\n", err);
        gcry_ctx_release(ctx);
        output->errorCode = FUZZEC_ERROR_UNKNOWN;
        return;
    }
    err = gcry_mpi_scan(&scalar2, GCRYMPI_FMT_USG, input->bignum2, input->bignum2Size, NULL);
    if (err) {
        gcry_mpi_release(scalar1);
        gcry_ctx_release(ctx);
        output->errorCode = FUZZEC_ERROR_UNKNOWN;
        return;
    }

    pointG = gcry_mpi_ec_get_point ("g", ctx, 1);
    if (!pointG) {
        output->errorCode = FUZZEC_ERROR_UNKNOWN;
        goto end;
    }
    point1 = gcry_mpi_point_new(0);
    point2 = gcry_mpi_point_new(0);
    point3 = gcry_mpi_point_new(0);

    //elliptic curve computations
    //P1=scalar1*G
    gcry_mpi_ec_mul(point1, scalar1, pointG, ctx);
    //P2=scalar2*P1 (=scalar2*scalar1*G)
    gcry_mpi_ec_mul(point2, scalar2, point1, ctx);
    //P3=P1+P2
    gcry_mpi_ec_add(point3,point1, point2, ctx);

    //format output
    gcrypt_to_ecfuzzer(point1, output, 0, BYTECEIL(input->groupBitLen), ctx);
    gcrypt_to_ecfuzzer(point2, output, 1, BYTECEIL(input->groupBitLen), ctx);
    gcrypt_to_ecfuzzer(point3, output, 2, BYTECEIL(input->groupBitLen), ctx);

#ifdef DEBUG
    printf("gcrypt:");
    for (size_t j=0; j<FUZZEC_NBPOINTS; j++) {
        for (size_t i=0; i<output->pointSizes[j]; i++) {
            printf("%02x", output->points[j][i]);
        }
        printf("\n");
    }
#endif
    output->errorCode = FUZZEC_ERROR_NONE;

end:
    if (point1) {
        gcry_mpi_point_release(point1);
    }
    if (point2) {
        gcry_mpi_point_release(point2);
    }
    if (point3) {
        gcry_mpi_point_release(point3);
    }
    if (pointG) {
        gcry_mpi_point_release(pointG);
    }
    gcry_mpi_release(scalar2);
    gcry_mpi_release(scalar1);
    gcry_ctx_release(ctx);
    return;
}
