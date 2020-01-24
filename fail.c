// Copyright (c) 2020 Catena cyber
// Author Philippe Antoine <p.antoine@catenacyber.fr>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "fuzz_ec.h"

void secp192k1_fail(fuzzec_module_t *mod) {
    printf("fail for secp192k1\n");
    mod->fail();
}

void secp192r1_fail(fuzzec_module_t *mod) {
    printf("fail for secp192r1\n");
    mod->fail();
}

void secp224k1_fail(fuzzec_module_t *mod) {
    printf("fail for secp224k1\n");
    mod->fail();
}

void secp224r1_fail(fuzzec_module_t *mod) {
    printf("fail for secp224r1\n");
    mod->fail();
}

void secp256k1_fail(fuzzec_module_t *mod) {
    printf("fail for secp256k1\n");
    mod->fail();
}

void secp256r1_fail(fuzzec_module_t *mod) {
    printf("fail for secp256r1\n");
    mod->fail();
}

void secp384r1_fail(fuzzec_module_t *mod) {
    printf("fail for secp384r1\n");
    mod->fail();
}

void secp521r1_fail(fuzzec_module_t *mod) {
    printf("fail for secp521r1\n");
    mod->fail();
}

void brainpool256r1_fail(fuzzec_module_t *mod) {
    printf("fail for brainpool256r1\n");
    mod->fail();
}

void brainpool384r1_fail(fuzzec_module_t *mod) {
    printf("fail for brainpool384r1\n");
    mod->fail();
}

void brainpool521r1_fail(fuzzec_module_t *mod) {
    printf("fail for brainpool521r1\n");
    mod->fail();
}

void unknown_fail(fuzzec_module_t *mod) {
    printf("fail for unknown\n");
    mod->fail();
}
