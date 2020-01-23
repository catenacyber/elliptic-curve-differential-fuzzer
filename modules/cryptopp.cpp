// Copyright (c) 2018 Catena cyber
// Author Philippe Antoine <p.antoine@catenacyber.fr>


#include "../fuzz_ec.h"
#include <cryptopp/eccrypto.h>
#include <cryptopp/ecp.h>
#include <cryptopp/oids.h>
#include <stdlib.h>

static const CryptoPP::OID eccurvetypeFromTlsId(uint16_t tlsid) {
    switch (tlsid) {
        case 18:
            return CryptoPP::ASN1::secp192k1();
        case 19:
            return CryptoPP::ASN1::secp192r1();
        case 20:
            return CryptoPP::ASN1::secp224k1();
        case 21:
            return CryptoPP::ASN1::secp224r1();
        case 22:
            return CryptoPP::ASN1::secp256k1();
        case 23:
            return CryptoPP::ASN1::secp256r1();
        case 24:
            return CryptoPP::ASN1::secp384r1();
        case 25:
            return CryptoPP::ASN1::secp521r1();
        case 26:
            return CryptoPP::ASN1::brainpoolP256r1();
        case 27:
            return CryptoPP::ASN1::brainpoolP384r1();
        case 28:
            return CryptoPP::ASN1::brainpoolP512r1();
    }
    return NULL;
}

extern "C" void fuzzec_cryptopp_process(fuzzec_input_t * input, fuzzec_output_t * output) {

    //initialize
    const CryptoPP::OID oid = eccurvetypeFromTlsId(input->tls_id);
    if (oid == NULL) {
        output->errorCode = FUZZEC_ERROR_UNSUPPORTED;
        return;
    }
    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> params(oid);
    CryptoPP::ECP ec = params.GetCurve();
    CryptoPP::Integer coordx(input->coordx, input->coordSize);
    CryptoPP::Integer coordy(input->coordy, input->coordSize);
    CryptoPP::ECP::Point point1(coordx, coordy);
    CryptoPP::Integer scalar1(input->bignum, input->bignumSize);

    //elliptic curve computations
    //P2=scalar2*P1
    CryptoPP::ECP::Point point2(ec.Multiply(scalar1, point1));

    //format output
    ec.EncodePoint(output->points[0], point2, false);
    if (output->points[0][0] == 0) {
        output->pointSizes[0] = 1;
    } else {
        output->pointSizes[0] = ec.EncodedPointSize();
    }

#ifdef DEBUG
    printf("cryptopp:");
    for (size_t j=0; j<FUZZEC_NBPOINTS; j++) {
        for (size_t i=0; i<output->pointSizes[j]; i++) {
            printf("%02x", output->points[j][i]);
        }
        printf("\n");
    }
#endif
    output->errorCode = FUZZEC_ERROR_NONE;

    return;
}

extern "C" void fuzzec_cryptopp_fail() {
    printf("fail for cryptopp\n");
#ifndef DEBUG
    abort();
#endif
}
