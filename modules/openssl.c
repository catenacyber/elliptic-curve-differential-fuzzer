// Copyright (c) 2018 Catena cyber
// Author Philippe Antoine <p.antoine@catenacyber.fr>


#include "../fuzz_ec.h"
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <string.h>
#include <stdlib.h>

static const int nid_list[28] = {
    NID_sect163k1, /* sect163k1 (1) */
    NID_sect163r1, /* sect163r1 (2) */
    NID_sect163r2, /* sect163r2 (3) */
    NID_sect193r1, /* sect193r1 (4) */
    NID_sect193r2, /* sect193r2 (5) */
    NID_sect233k1, /* sect233k1 (6) */
    NID_sect233r1, /* sect233r1 (7) */
    NID_sect239k1, /* sect239k1 (8) */
    NID_sect283k1, /* sect283k1 (9) */
    NID_sect283r1, /* sect283r1 (10) */
    NID_sect409k1, /* sect409k1 (11) */
    NID_sect409r1, /* sect409r1 (12) */
    NID_sect571k1, /* sect571k1 (13) */
    NID_sect571r1, /* sect571r1 (14) */
    NID_secp160k1, /* secp160k1 (15) */
    NID_secp160r1, /* secp160r1 (16) */
    NID_secp160r2, /* secp160r2 (17) */
    NID_secp192k1, /* secp192k1 (18) */
    NID_X9_62_prime192v1, /* secp192r1 (19) */
    NID_secp224k1, /* secp224k1 (20) */
    NID_secp224r1, /* secp224r1 (21) */
    NID_secp256k1, /* secp256k1 (22) */
    NID_X9_62_prime256v1, /* secp256r1 (23) */
    NID_secp384r1, /* secp384r1 (24) */
    NID_secp521r1, /* secp521r1 (25) */
    NID_brainpoolP256r1, /* brainpoolP256r1 (26) */
    NID_brainpoolP384r1, /* brainpoolP384r1 (27) */
    NID_brainpoolP512r1, /* brainpool512r1 (28) */
};

static int tls1_group_id_lookup(uint16_t tlsid) {
    if (tlsid < 1 || tlsid > 28)
        return 0;
    return nid_list[tlsid - 1];
}

int decompressPoint(const uint8_t *Data, int compBit, size_t Size, uint8_t *decom, uint16_t tls_id, size_t coordlen) {
    int r;
    EC_GROUP * group = NULL;
    BIGNUM * coordx = NULL;
    EC_POINT * point = NULL;
    uint8_t * buffer = NULL;

    group = EC_GROUP_new_by_curve_name(tls1_group_id_lookup(tls_id));
    if (group == NULL) {
        r = 1;
        goto end;
    }

    point = EC_POINT_new(group);
    coordx = BN_bin2bn(Data+1, Size-1, NULL);

    if (EC_POINT_set_compressed_coordinates_GFp(group, point,  coordx, compBit, NULL) == 0) {
        r = 2;
        goto end;
    }
    if (EC_POINT_is_on_curve(group, point, NULL) == 0) {
        r = 3;
        goto end;
    }
    r = EC_POINT_point2buf(group, point, POINT_CONVERSION_UNCOMPRESSED, &buffer, NULL);
    if (r == 0) {
        r = 4;
        goto end;
    }
    memcpy(decom, buffer, r);
    r = 0;
    free(buffer);
end:
    EC_GROUP_clear_free(group);
    BN_clear_free(coordx);
    EC_POINT_clear_free(point);
    return r;
}


void fuzzec_openssl_process(fuzzec_input_t * input, fuzzec_output_t * output) {
    EC_GROUP * group = NULL;
    BIGNUM * scalar1 = NULL;
    BIGNUM * scalar2 = NULL;
    EC_POINT * point1 = NULL;
    EC_POINT * point2 = NULL;
    uint8_t * buffer = NULL;

    //initialize
    group = EC_GROUP_new_by_curve_name(tls1_group_id_lookup(input->tls_id));
    if (group == NULL) {
        printf("fail %d\n", input->tls_id);
        output->errorCode = FUZZEC_ERROR_UNSUPPORTED;
        return;
    }
    point1 = EC_POINT_new(group);
    point2 = EC_POINT_new(group);
    scalar1 = BN_bin2bn(input->coordx, input->coordSize, NULL);
    scalar2 = BN_bin2bn(input->coordy, input->coordSize, NULL);

    if (EC_POINT_set_affine_coordinates_GFp(group, point1, scalar1, scalar2, NULL) == 0) {
        output->errorCode = FUZZEC_ERROR_UNKNOWN;
        goto end;
    }
    BN_clear_free(scalar1);
    scalar1 = BN_bin2bn(input->bignum, input->bignumSize, NULL);

    //elliptic curve computations
    //P2=scalar1*P1
    if (EC_POINT_mul(group, point2, NULL, point1, scalar1, NULL) == 0){
        output->errorCode = FUZZEC_ERROR_UNKNOWN;
        goto end;
    }

    //format output
    output->pointSizes[0] = EC_POINT_point2buf(group, point2, POINT_CONVERSION_UNCOMPRESSED, &buffer, NULL);
    if (output->pointSizes[0] == 0 ) {
        output->errorCode = FUZZEC_ERROR_UNKNOWN;
        goto end;
    }
    memcpy(output->points[0], buffer, output->pointSizes[0]);
    free(buffer);

#ifdef DEBUG
    printf("openssl:");
    for (size_t j=0; j<FUZZEC_NBPOINTS; j++) {
        for (size_t i=0; i<output->pointSizes[j]; i++) {
            printf("%02x", output->points[j][i]);
        }
        printf("\n");
    }
#endif
    output->errorCode = FUZZEC_ERROR_NONE;

end:
    EC_GROUP_clear_free(group);
    BN_clear_free(scalar1);
    BN_clear_free(scalar2);
    EC_POINT_clear_free(point1);
    EC_POINT_clear_free(point2);
    return;
}


void fuzzec_openssl_add(fuzzec_input_t * input, fuzzec_output_t * output) {
    EC_GROUP * group = NULL;
    BIGNUM * scalar1 = NULL;
    BIGNUM * scalar2 = NULL;
    EC_POINT * point1 = NULL;
    EC_POINT * point2 = NULL;
    EC_POINT * point3 = NULL;
    uint8_t * buffer = NULL;

    //initialize
    group = EC_GROUP_new_by_curve_name(tls1_group_id_lookup(input->tls_id));
    if (group == NULL) {
        printf("fail %d\n", input->tls_id);
        output->errorCode = FUZZEC_ERROR_UNSUPPORTED;
        return;
    }
    point1 = EC_POINT_new(group);
    point2 = EC_POINT_new(group);
    point3 = EC_POINT_new(group);
    scalar1 = BN_bin2bn(input->coordx, input->coordSize, NULL);
    scalar2 = BN_bin2bn(input->coordy, input->coordSize, NULL);
    if (EC_POINT_set_affine_coordinates_GFp(group, point1, scalar1, scalar2, NULL) == 0) {
        output->errorCode = FUZZEC_ERROR_UNKNOWN;
        goto end;
    }
    BN_clear_free(scalar1);
    BN_clear_free(scalar2);
    scalar1 = BN_bin2bn(input->coord2x, input->coordSize, NULL);
    scalar2 = BN_bin2bn(input->coord2y, input->coordSize, NULL);
    if (EC_POINT_set_affine_coordinates_GFp(group, point2, scalar1, scalar2, NULL) == 0) {
        output->errorCode = FUZZEC_ERROR_UNKNOWN;
        goto end;
    }

    //elliptic curve computations
    //P3=P2+P1
    if (EC_POINT_add(group, point3, point2, point1, NULL) == 0){
        output->errorCode = FUZZEC_ERROR_UNKNOWN;
        goto end;
    }

    //format output
    output->pointSizes[0] = EC_POINT_point2buf(group, point3, POINT_CONVERSION_UNCOMPRESSED, &buffer, NULL);
    if (output->pointSizes[0] == 0 ) {
        output->errorCode = FUZZEC_ERROR_UNKNOWN;
        goto end;
    }
    memcpy(output->points[0], buffer, output->pointSizes[0]);
    free(buffer);

#ifdef DEBUG
    printf("openssl:");
    for (size_t j=0; j<FUZZEC_NBPOINTS; j++) {
        for (size_t i=0; i<output->pointSizes[j]; i++) {
            printf("%02x", output->points[j][i]);
        }
        printf("\n");
    }
#endif
    output->errorCode = FUZZEC_ERROR_NONE;

end:
    EC_GROUP_clear_free(group);
    BN_clear_free(scalar1);
    BN_clear_free(scalar2);
    EC_POINT_clear_free(point1);
    EC_POINT_clear_free(point2);
    EC_POINT_clear_free(point3);
    return;
}

void fuzzec_openssl_fail() {
    printf("fail for openssl\n");
#ifndef DEBUG
    abort();
#endif
}
