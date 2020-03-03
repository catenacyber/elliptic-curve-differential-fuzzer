// Copyright (c) 2018 Catena cyber
// Author Philippe Antoine <p.antoine@catenacyber.fr>


#include "../fuzz_ec.h"
#include <mbedtls/ecp.h>
#include <stdlib.h>

void fuzzec_mbedtls_process(fuzzec_input_t * input, fuzzec_output_t * output) {
    mbedtls_ecp_group group;
    const mbedtls_ecp_curve_info *curve_info;
    mbedtls_mpi scalar1;
    mbedtls_ecp_point point1;
    mbedtls_ecp_point point2;
    int r;

    mbedtls_ecp_group_init(&group);
    mbedtls_mpi_init(&scalar1);
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
    if (mbedtls_mpi_read_binary(&scalar1, input->bignum, input->bignumSize)) {
        output->errorCode = FUZZEC_ERROR_UNKNOWN;
        goto end;
    }
    if (mbedtls_ecp_point_read_binary( &group, &point1, input->coord, 2*input->coordSize+1)){
        output->errorCode = FUZZEC_ERROR_UNKNOWN;
        goto end;
    }

    //elliptic curve computations
    //P2=scalar1*P1
    if (mbedtls_mpi_cmp_int(&scalar1, 0) == 0) {
        //multiplication by 0 is MBEDTLS_ERR_ECP_BAD_INPUT_DATA
        mbedtls_ecp_set_zero(&point1);
    }
    else {
        r = mbedtls_ecp_mul(&group, &point2, &scalar1, &point1, NULL, NULL);
        if (r == MBEDTLS_ERR_ECP_INVALID_KEY) {
            //mbedtls enforces the scalar to be lesser than curve order
            output->errorCode = FUZZEC_ERROR_UNSUPPORTED;
            goto end;
        }
        else if (r != 0) {
            output->errorCode = FUZZEC_ERROR_UNKNOWN;
            goto end;
        }
    }

    //format output
    if (mbedtls_ecp_point_write_binary(&group, &point2, MBEDTLS_ECP_PF_UNCOMPRESSED, &output->pointSizes[0], output->points[0], FUZZEC_MAXPOINTLEN) != 0 ) {
        output->errorCode = FUZZEC_ERROR_UNKNOWN;
        goto end;
    }
    output->errorCode = FUZZEC_ERROR_NONE;

end:
    mbedtls_mpi_free(&scalar1);
    mbedtls_ecp_point_free(&point1);
    mbedtls_ecp_point_free(&point2);
    mbedtls_ecp_group_free(&group);
    return;
}

void fuzzec_mbedtls_add(fuzzec_input_t * input, fuzzec_output_t * output) {
    mbedtls_ecp_group group;
    const mbedtls_ecp_curve_info *curve_info;
    mbedtls_ecp_point point1;
    mbedtls_ecp_point point2;
    mbedtls_ecp_point point3;
    mbedtls_mpi scalar1;
    int r;

    mbedtls_ecp_group_init(&group);
    mbedtls_mpi_init(&scalar1);
    mbedtls_ecp_point_init(&point1);
    mbedtls_ecp_point_init(&point2);
    mbedtls_ecp_point_init(&point3);

    //initialize
    if (mbedtls_mpi_lset(&scalar1, 1) != 0) {
        output->errorCode = FUZZEC_ERROR_UNKNOWN;
        goto end;
    }
    if( ( curve_info = mbedtls_ecp_curve_info_from_tls_id( input->tls_id ) ) == NULL ) {
        output->errorCode = FUZZEC_ERROR_UNSUPPORTED;
        goto end;
    }
    if (mbedtls_ecp_group_load( &group, curve_info->grp_id ) != 0) {
        output->errorCode = FUZZEC_ERROR_UNKNOWN;
        goto end;
    }
    if (mbedtls_ecp_point_read_binary( &group, &point1, input->coord, 2*input->coordSize+1)){
        output->errorCode = FUZZEC_ERROR_UNKNOWN;
        goto end;
    }
    if (mbedtls_ecp_point_read_binary( &group, &point2, input->coord2, 2*input->coordSize+1)){
        output->errorCode = FUZZEC_ERROR_UNKNOWN;
        goto end;
    }

    //elliptic curve computations
    //P3=P2+P1
    r = mbedtls_ecp_muladd(&group, &point3, &scalar1, &point2, &scalar1, &point1);
    if (r == MBEDTLS_ERR_ECP_INVALID_KEY) {
        //mbedtls enforces the scalar to be lesser than curve order
        output->errorCode = FUZZEC_ERROR_UNSUPPORTED;
        goto end;
    }
    else if (r != 0) {
        output->errorCode = FUZZEC_ERROR_UNKNOWN;
        goto end;
    }

    //format output
    if (mbedtls_ecp_point_write_binary(&group, &point3, MBEDTLS_ECP_PF_UNCOMPRESSED, &output->pointSizes[0], output->points[0], FUZZEC_MAXPOINTLEN) != 0 ) {
        output->errorCode = FUZZEC_ERROR_UNKNOWN;
        goto end;
    }
    output->errorCode = FUZZEC_ERROR_NONE;

end:
    mbedtls_mpi_free(&scalar1);
    mbedtls_ecp_point_free(&point1);
    mbedtls_ecp_point_free(&point2);
    mbedtls_ecp_point_free(&point3);
    mbedtls_ecp_group_free(&group);
    return;
}
