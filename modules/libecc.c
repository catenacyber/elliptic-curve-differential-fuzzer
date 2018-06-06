// Copyright (c) 2018 Catena cyber
// Author Philippe Antoine <p.antoine@catenacyber.fr>


#include "../fuzz_ec.h"
#include <libec.h>

ec_curve_type eccurvetypeFromTlsId(uint16_t tlsid) {
    switch (tlsid) {
        //TODO use curves GOST and FRP256V1
        case 19:
            return SECP192R1;
        case 21:
            return SECP224R1;
        case 23:
            return SECP256R1;
        case 24:
            return SECP384R1;
        case 25:
            return SECP521R1;
        case 26:
            return BRAINPOOLP256R1;
        case 27:
            return BRAINPOOLP384R1;
        case 28:
            return BRAINPOOLP512R1;
    }
    return UNKNOWN_CURVE;
}
void fuzzec_libecc_process(fuzzec_input_t * input, fuzzec_output_t * output) {
    const ec_str_params *the_curve_const_parameters;
    ec_params curve_params;
    nn scalar1;
    prj_pt pointZ1;
    aff_pt point1;
    size_t byteLen;

    //initialize
    the_curve_const_parameters = ec_get_curve_params_by_type(eccurvetypeFromTlsId(input->tls_id));
    if (the_curve_const_parameters == NULL) {
        output->errorCode = FUZZEC_ERROR_UNSUPPORTED;
        return;
    }
    import_params(&curve_params, the_curve_const_parameters);
    prj_pt_init(&pointZ1, &(curve_params.ec_curve));
    nn_init_from_buf(&scalar1, input->bignum1, input->bignum1Size);

    if (nn_iszero(&scalar1)) {
        //multiplication by 0 is not allowed
        output->pointSizes[0] = 1;
        output->points[0][0] = 0;
        output->errorCode = FUZZEC_ERROR_NONE;
        goto end;
    }
    //elliptic curve computations
    prj_pt_mul(&pointZ1, &scalar1, &(curve_params.ec_gen));
    //TODO test consistency with prj_pt_mul_monty
    if (prj_pt_iszero(&pointZ1)) {
        //null point is zero
        output->pointSizes[0] = 1;
        output->points[0][0] = 0;
        output->errorCode = FUZZEC_ERROR_NONE;
        goto end;
    }
    prj_pt_to_aff(&point1, &pointZ1);

    //format output
    byteLen = BYTECEIL(curve_params.ec_fp.p_bitlen);
    output->pointSizes[0] = 1 + 2 * byteLen;
    //uncompressed form
    output->points[0][0] = 4;
    fp_export_to_buf(output->points[0]+1, byteLen, &(point1.x));
    fp_export_to_buf(output->points[0]+ 1+byteLen, byteLen, &(point1.y));

#ifdef DEBUG
    printf("libecc:");
    for (size_t i=0; i<output->pointSizes[0]; i++) {
        printf("%02x", output->points[0][i]);
    }
    printf("\n");
#endif
    output->errorCode = FUZZEC_ERROR_NONE;
    aff_pt_uninit(&point1);

end:
    prj_pt_uninit(&pointZ1);
    nn_uninit(&scalar1);
    return;
}
