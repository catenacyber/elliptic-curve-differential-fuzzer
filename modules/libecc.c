// Copyright (c) 2018 Catena cyber
// Author Philippe Antoine <p.antoine@catenacyber.fr>


#include "../fuzz_ec.h"
#include <libec.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

static ec_curve_type eccurvetypeFromTlsId(uint16_t tlsid) {
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

static void libecc_to_ecfuzzer(prj_pt *pointZ, fuzzec_output_t * output, size_t index, size_t byteLen) {
    aff_pt point;

    if (prj_pt_iszero(pointZ)) {
        //null point is zero
        output->pointSizes[index] = 1;
        output->points[index][0] = 0;
        output->errorCode = FUZZEC_ERROR_NONE;
        return;
    }
    prj_pt_to_aff(&point, pointZ);

    output->pointSizes[index] = 1 + 2 * byteLen;
    //uncompressed form
    output->points[index][0] = 4;
    fp_export_to_buf(output->points[index]+1, byteLen, &(point.x));
    fp_export_to_buf(output->points[index]+1+byteLen, byteLen, &(point.y));
    aff_pt_uninit(&point);
}

void fuzzec_libecc_process_aux(fuzzec_input_t * input, fuzzec_output_t * output, void (*multiplyFunction)(prj_pt_t, nn_src_t, prj_pt_src_t)) {
    const ec_str_params *the_curve_const_parameters;
    ec_params curve_params;
    nn scalar1;
    fp coordx;
    fp coordy;
    fp coordz;
    prj_pt pointZ1;
    prj_pt pointZ2;
    size_t byteLen;

    //initialize
    the_curve_const_parameters = ec_get_curve_params_by_type(eccurvetypeFromTlsId(input->tls_id));
    if (the_curve_const_parameters == NULL) {
        output->errorCode = FUZZEC_ERROR_UNSUPPORTED;
        return;
    }
    import_params(&curve_params, the_curve_const_parameters);
    prj_pt_init(&pointZ2, &(curve_params.ec_curve));
    fp_init_from_buf(&coordx, &(curve_params.ec_fp), input->coordx, input->coordSize);
    fp_init_from_buf(&coordy, &(curve_params.ec_fp), input->coordy, input->coordSize);
    fp_init(&coordz, &(curve_params.ec_fp));
    fp_one(&coordz);
    prj_pt_init_from_coords(&pointZ1, &(curve_params.ec_curve), &coordx, &coordy, &coordz);
    fp_uninit(&coordx);
    fp_uninit(&coordy);
    fp_uninit(&coordz);
    nn_init_from_buf(&scalar1, input->bignum, input->bignumSize);

    //elliptic curve computations
    //P2=scalar2*P1
    if (nn_iszero(&scalar1)) {
        //multiplication by 0 is not allowed
        prj_pt_zero(&pointZ2);
    } else {
        multiplyFunction(&pointZ2, &scalar1, &pointZ1);
    }

    //format output
    byteLen = ECDF_BYTECEIL(curve_params.ec_fp.p_bitlen);
    libecc_to_ecfuzzer(&pointZ2, output, 0, byteLen);

#ifdef DEBUG
    printf("libecc:");
    for (size_t j=0; j<FUZZEC_NBPOINTS; j++) {
        for (size_t i=0; i<output->pointSizes[j]; i++) {
            printf("%02x", output->points[j][i]);
        }
        printf("\n");
    }
#endif
    output->errorCode = FUZZEC_ERROR_NONE;

    prj_pt_uninit(&pointZ1);
    prj_pt_uninit(&pointZ2);
    nn_uninit(&scalar1);
    return;
}

void fuzzec_libecc_montgomery_process(fuzzec_input_t * input, fuzzec_output_t * output) {
    fuzzec_libecc_process_aux(input, output, prj_pt_mul_monty);
}

void fuzzec_libecc_process(fuzzec_input_t * input, fuzzec_output_t * output) {
    fuzzec_libecc_process_aux(input, output, prj_pt_mul);
}

void fuzzec_libecc_add(fuzzec_input_t * input, fuzzec_output_t * output) {
    const ec_str_params *the_curve_const_parameters;
    ec_params curve_params;
    fp coordx;
    fp coordy;
    fp coordz;
    prj_pt pointZ1;
    prj_pt pointZ2;
    prj_pt pointZ3;
    size_t byteLen;

    //initialize
    the_curve_const_parameters = ec_get_curve_params_by_type(eccurvetypeFromTlsId(input->tls_id));
    if (the_curve_const_parameters == NULL) {
        output->errorCode = FUZZEC_ERROR_UNSUPPORTED;
        return;
    }
    import_params(&curve_params, the_curve_const_parameters);
    prj_pt_init(&pointZ3, &(curve_params.ec_curve));
    fp_init_from_buf(&coordx, &(curve_params.ec_fp), input->coordx, input->coordSize);
    fp_init_from_buf(&coordy, &(curve_params.ec_fp), input->coordy, input->coordSize);
    fp_init(&coordz, &(curve_params.ec_fp));
    fp_one(&coordz);
    prj_pt_init_from_coords(&pointZ1, &(curve_params.ec_curve), &coordx, &coordy, &coordz);
    fp_uninit(&coordx);
    fp_uninit(&coordy);
    fp_uninit(&coordz);
    fp_init_from_buf(&coordx, &(curve_params.ec_fp), input->coord2x, input->coordSize);
    fp_init_from_buf(&coordy, &(curve_params.ec_fp), input->coord2y, input->coordSize);
    fp_init(&coordz, &(curve_params.ec_fp));
    fp_one(&coordz);
    prj_pt_init_from_coords(&pointZ2, &(curve_params.ec_curve), &coordx, &coordy, &coordz);
    fp_uninit(&coordx);
    fp_uninit(&coordy);
    fp_uninit(&coordz);

    //elliptic curve computations
    //P3=P2+P1
    prj_pt_add(&pointZ3, &pointZ2, &pointZ1);

    //format output
    byteLen = ECDF_BYTECEIL(curve_params.ec_fp.p_bitlen);
    libecc_to_ecfuzzer(&pointZ3, output, 0, byteLen);

#ifdef DEBUG
    printf("libecc:");
    for (size_t j=0; j<FUZZEC_NBPOINTS; j++) {
        for (size_t i=0; i<output->pointSizes[j]; i++) {
            printf("%02x", output->points[j][i]);
        }
        printf("\n");
    }
#endif
    output->errorCode = FUZZEC_ERROR_NONE;

    prj_pt_uninit(&pointZ1);
    prj_pt_uninit(&pointZ2);
    prj_pt_uninit(&pointZ3);
    return;
}

static int fimport(unsigned char *buf, u16 buflen, const char *path)
{
    u16 rem = buflen, copied = 0;
    ssize_t ret;
    int fd;
    fd = open(path, O_RDONLY);
    if (fd == -1) {
        printf("Unable to open input file %s\n", path);
        return -1;
    }
    while (rem) {
        ret = (int)read(fd, buf + copied, rem);
        if (ret <= 0) {
            break;
        } else {
            rem -= (u16)ret;
            copied += (u16)ret;
        }
    }
    close(fd);
    return (copied == buflen) ? 0 : -1;
}

int get_random(unsigned char *buf, u16 len)
{
    return fimport(buf, len, "/dev/urandom");
}
