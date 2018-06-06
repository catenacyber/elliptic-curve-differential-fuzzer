// Copyright (c) 2018 Catena cyber
// Author Philippe Antoine <p.antoine@catenacyber.fr>


#include "../fuzz_ec.h"
#include <mbedtls/ecp.h>

void fuzzec_mbedtls_process(fuzzec_input_t * input, fuzzec_output_t * output) {
    mbedtls_ecp_group group;
    const mbedtls_ecp_curve_info *curve_info;
    mbedtls_mpi scalar1;
    mbedtls_mpi scalar2;
    mbedtls_ecp_point point1;
    mbedtls_ecp_point point2;

    mbedtls_ecp_group_init(&group);
    mbedtls_mpi_init(&scalar1);
    mbedtls_mpi_init(&scalar2);
    mbedtls_ecp_point_init(&point1);
    mbedtls_ecp_point_init(&point2);

    //initialize
    if( ( curve_info = mbedtls_ecp_curve_info_from_tls_id( input->tls_id ) ) == NULL ) {
        output->errorCode = FUZZEC_ERROR_UNSUPPORTED;
        goto end;
    }
    if (mbedtls_ecp_group_load( &group, curve_info->grp_id ) != 0) {
        output->errorCode = FUZZEC_ERROR_UNKNOWN;
        goto end;
    }
    if (mbedtls_mpi_read_binary(&scalar1, input->bignum1, input->bignum1Size)) {
        output->errorCode = FUZZEC_ERROR_UNKNOWN;
        goto end;
    }
    if (mbedtls_mpi_read_binary(&scalar2, input->bignum2, input->bignum2Size)) {
        output->errorCode = FUZZEC_ERROR_UNKNOWN;
        goto end;
    }

    //elliptic curve computations
    //P1=scalar1*G
    if (mbedtls_mpi_cmp_int(&scalar1, 0) == 0) {
        //multiplication by 0 is MBEDTLS_ERR_ECP_BAD_INPUT_DATA
        mbedtls_ecp_set_zero(&point1);
    }
    else {
        if (mbedtls_ecp_mul(&group, &point1, &scalar1, &group.G, NULL, NULL) != 0) {
            output->errorCode = FUZZEC_ERROR_UNKNOWN;
            goto end;
        }
    }
    if (mbedtls_mpi_cmp_int(&scalar2, 0) == 0 || mbedtls_ecp_is_zero(&point1)) {
        mbedtls_ecp_set_zero(&point2);
    }
    else {
        if (mbedtls_ecp_mul(&group, &point2, &scalar2, &point1, NULL, NULL) != 0) {
            output->errorCode = FUZZEC_ERROR_UNKNOWN;
            goto end;
        }
    }
    //P2=scalar2*P1 (=scalar2*scalar1*G)

    //format output
    if (mbedtls_ecp_point_write_binary(&group, &point1, MBEDTLS_ECP_PF_UNCOMPRESSED, &output->pointSizes[0], output->points[0], FUZZEC_MAXPOINTLEN) != 0 ) {
        output->errorCode = FUZZEC_ERROR_UNKNOWN;
        goto end;
    }
    if (mbedtls_ecp_point_write_binary(&group, &point2, MBEDTLS_ECP_PF_UNCOMPRESSED, &output->pointSizes[1], output->points[1], FUZZEC_MAXPOINTLEN) != 0 ) {
        output->errorCode = FUZZEC_ERROR_UNKNOWN;
        goto end;
    }
#ifdef DEBUG
    printf("mbedlts:");
    for (size_t j=0; j<FUZZEC_NBPOINTS; j++) {
        for (size_t i=0; i<output->pointSizes[j]; i++) {
            printf("%02x", output->points[j][i]);
        }
        printf("\n");
    }
#endif
    output->errorCode = FUZZEC_ERROR_NONE;

end:
    mbedtls_mpi_free(&scalar1);
    mbedtls_mpi_free(&scalar2);
    mbedtls_ecp_point_free(&point1);
    mbedtls_ecp_point_free(&point2);
    mbedtls_ecp_group_free(&group);
    return;
}
