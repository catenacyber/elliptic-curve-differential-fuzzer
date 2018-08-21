// Copyright (c) 2018 Catena cyber
// Author Philippe Antoine <p.antoine@catenacyber.fr>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fuzz_ec.h"

size_t bitlenFromTlsId(uint16_t tlsid) {
    switch (tlsid) {
        //TODO complete curves from TLS
        case 18:
            //secp192k1
            return 192;
        case 19:
            //secp192r1
            return 192;
        case 20:
            //secp224k1
            return 224;
        case 21:
            //secp224r1
            return 224;
        case 22:
            //secp256k1
            return 256;
        case 23:
            //secp256r1
            return 256;
        case 24:
            //secp384r1
            return 384;
        case 25:
            //secp521r1
            return 521;
        case 26:
            //brainpoolP256r1
            return 256;
        case 27:
            //brainpoolP384r1
            return 384;
        case 28:
            //brainpoolP512r1
            return 512;
    }
    return 0;
}

#define NBMODULES 7
//TODO integrate more modules
void fuzzec_mbedtls_process(fuzzec_input_t * input, fuzzec_output_t * output);
void fuzzec_libecc_process(fuzzec_input_t * input, fuzzec_output_t * output);
void fuzzec_libecc_montgomery_process(fuzzec_input_t * input, fuzzec_output_t * output);
void fuzzec_openssl_process(fuzzec_input_t * input, fuzzec_output_t * output);
void fuzzec_nettle_process(fuzzec_input_t * input, fuzzec_output_t * output);
void fuzzec_gcrypt_process(fuzzec_input_t * input, fuzzec_output_t * output);
int fuzzec_gcrypt_init();
void fuzzec_cryptopp_process(fuzzec_input_t * input, fuzzec_output_t * output);
fuzzec_module_t modules[NBMODULES] = {
    {
        "mbedtls",
        fuzzec_mbedtls_process,
        NULL,
    },
    {
        "libecc",
        fuzzec_libecc_process,
        NULL,
    },
    {
        "libecc_montgomery",
        fuzzec_libecc_montgomery_process,
        NULL,
    },
    {
        "openssl",
        fuzzec_openssl_process,
        NULL,
    },
    {
        "nettle",
        fuzzec_nettle_process,
        NULL,
    },
    {
        "gcrypt",
        fuzzec_gcrypt_process,
        fuzzec_gcrypt_init,
    },
    {
        "cryptopp",
        fuzzec_cryptopp_process,
        NULL,
    },
};

static int initialized = 0;

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    fuzzec_input_t input;
    fuzzec_output_t output[NBMODULES];
    size_t i, k;

    if (initialized == 0) {
        for (i=0; i<NBMODULES; i++) {
            if (modules[i].init) {
                if (modules[i].init()) {
                    printf("Failed init for module %s\n", modules[i].name);
                    return 0;
                }
            }
        }
        initialized = 1;
    }
    if (Size < 4) {
        //2 bytes for TLS group, 1 for each of two big integers
        return 0;
    }
    //splits Data in tlsid, big nuber 1, big number 2
    input.tls_id = (Data[0] << 8) | Data[1];
    input.groupBitLen = bitlenFromTlsId(input.tls_id);
    if (input.groupBitLen == 0) {
        //unsupported curve
        return 0;
    }

    Size -= 2;
    input.bignum1 = Data + 2;
    if (Size > 2 * ((input.groupBitLen >> 3) + ((input.groupBitLen & 0x7) ? 1 : 0))) {
        Size = 2 * ((input.groupBitLen >> 3) + ((input.groupBitLen & 0x7) ? 1 : 0));
    }
    input.bignum1Size = Size/2;
    input.bignum2 = input.bignum1 + input.bignum1Size;
    input.bignum2Size = Size - input.bignum1Size;

    //iterate modules
    for (i=0; i<NBMODULES; i++) {
        modules[i].process(&input, &output[i]);
        if (output[i].errorCode == FUZZEC_ERROR_NONE) {
            if (i > 0) {
                if (output[i-1].errorCode != FUZZEC_ERROR_NONE) {
                    continue;
                }
                for (k=0; k<FUZZEC_NBPOINTS; k++) {
                    if (output[i].pointSizes[k] == 0 ||
                        output[i-1].pointSizes[k] == 0) {
                        continue;
                    }
                    if (output[i].pointSizes[k] != output[i-1].pointSizes[k]) {
                        printf("Module %s and %s returned different lengths for test %zu : %zu vs %zu\n", modules[i].name, modules[i-1].name, k, output[i].pointSizes[k], output[i-1].pointSizes[k]);
                        abort();
                    }
                    if (memcmp(output[i].points[k], output[i-1].points[k], output[i].pointSizes[k]) != 0) {
                        printf("Module %s and %s returned different points for test %zu\n", modules[i].name, modules[i-1].name, k);
                        abort();
                    }
                }
            }
        } else if (output[i].errorCode != FUZZEC_ERROR_UNSUPPORTED) {
            printf("Module %s returned %d\n", modules[i].name, output[i].errorCode);
            abort();
        }
    }

    return 0;
}
