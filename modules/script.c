// Copyright (c) 2020 Catena cyber
// Author Philippe Antoine <p.antoine@catenacyber.fr>


#include "../fuzz_ec.h"
#include <quickjs-libc.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#include "genjsinit.h"
#include "genjsmult.h"
#include "genjsadd.h"

static const char * nameOfCurve(uint16_t tlsid) {
    switch (tlsid) {
        case 19:
            return "p192";
        case 21:
            return "p224";
        case 22:
            return "secp256k1";
        case 23:
            return "p256";
        case 24:
            return "p384";
        case 25:
            return "p521";
    }
    return NULL;
}

JSRuntime *rt;
JSContext *ctx;

int fuzzec_js_init() {
    rt = JS_NewRuntime();
    ctx = JS_NewContextRaw(rt);
    JS_SetModuleLoaderFunc(rt, NULL, js_module_loader, NULL);
    JS_AddIntrinsicBaseObjects(ctx);
    JS_AddIntrinsicDate(ctx);
    JS_AddIntrinsicEval(ctx);
    JS_AddIntrinsicStringNormalize(ctx);
    JS_AddIntrinsicRegExp(ctx);
    JS_AddIntrinsicJSON(ctx);
    JS_AddIntrinsicProxy(ctx);
    JS_AddIntrinsicMapSet(ctx);
    JS_AddIntrinsicTypedArrays(ctx);
    JS_AddIntrinsicPromise(ctx);
    JS_AddIntrinsicBigInt(ctx);
    js_std_add_helpers(ctx, 0, NULL);
    char cmd[2048];
    //global js variables outside browserify
    snprintf(cmd, 2048,"var EClib; var utils; var p192; var p224; var p256; var p384; var p521; var p256k;");
    JS_Eval(ctx, cmd, strlen(cmd), "<none>", JS_EVAL_TYPE_GLOBAL);
    js_std_eval_binary(ctx, genjsinit, genjsinit_size, 0);
    js_std_loop(ctx);
    return 0;
}

void fuzzec_js_aux(fuzzec_input_t * input, fuzzec_output_t * output, const uint8_t *bytecode, size_t bytecode_size) {
    js_std_eval_binary(ctx, bytecode, bytecode_size, 0);
    js_std_loop(ctx);

    JSValue global = JS_GetGlobalObject(ctx);
    JSValue val = JS_GetPropertyStr(ctx, global, "r");
    if (!JS_IsString(val)) {
        output->errorCode = FUZZEC_ERROR_UNKNOWN;
        return;
    }
    size_t plen;
    const char * result = JS_ToCStringLen(ctx, &plen, val);

    // hexdecode
    output->pointSizes[0] = plen/2;
    for (size_t i=0; i<output->pointSizes[0]; i++) {
        if (!isxdigit(result[2*i]) || !isxdigit(result[2*i+1])) {
            //invalid hexadecimal
            output->errorCode = FUZZEC_ERROR_UNKNOWN;
            return;
        }
        output->points[0][i] = (result[2*i] >= 'A' ? ((result[2*i] & 0xdf) - 'A') + 10 : (result[2*i] - '0')) << 4;
        output->points[0][i] |= (result[2*i+1] >= 'A' ? ((result[2*i+1] & 0xdf) - 'A') + 10 : (result[2*i+1] - '0'));
    }
#ifdef DEBUG
    printf("nodejs/elliptic:");
    for (size_t j=0; j<FUZZEC_NBPOINTS; j++) {
        for (size_t i=0; i<output->pointSizes[j]; i++) {
            printf("%02x", output->points[j][i]);
        }
        printf("\n");
    }
#endif
    output->errorCode = FUZZEC_ERROR_NONE;

}

void fuzzec_js_process(fuzzec_input_t * input, fuzzec_output_t * output) {
    char cmd[2048];
    const char *curve = nameOfCurve(input->tls_id);
    if (curve == NULL) {
        output->errorCode = FUZZEC_ERROR_UNSUPPORTED;
        return;
    }
    int offset = snprintf(cmd, 2048, "ec = %s;\ninputPoint='", curve);
    //dangerous overflow
    for (size_t i=0; i<2*input->coordSize+1; i++) {
        offset += snprintf(cmd+offset, 2048-offset, "%02x", input->coord[i]);
    }
    offset += snprintf(cmd+offset, 2048-offset, "';\ninputScalar='");
    for (size_t i=0; i<input->coordSize; i++) {
        offset += snprintf(cmd+offset, 2048-offset, "%02x", input->bignum[i]);
    }
    offset += snprintf(cmd+offset, 2048-offset, "';\n");

    JS_Eval(ctx, cmd, strlen(cmd), "<none>", JS_EVAL_TYPE_GLOBAL);
    fuzzec_js_aux(input, output, genjsmult, genjsmult_size);
}

void fuzzec_js_add(fuzzec_input_t * input, fuzzec_output_t * output) {
    char cmd[2048];
    const char *curve = nameOfCurve(input->tls_id);
    if (curve == NULL) {
        output->errorCode = FUZZEC_ERROR_UNSUPPORTED;
        return;
    }
    int offset = snprintf(cmd, 2048, "ec = %s;\ninputPoint='", curve);
    //dangerous overflow
    for (size_t i=0; i<2*input->coordSize+1; i++) {
        offset += snprintf(cmd+offset, 2048-offset, "%02x", input->coord[i]);
    }
    offset += snprintf(cmd+offset, 2048-offset, "';\ninputPoint2='");
    for (size_t i=0; i<2*input->coordSize+1; i++) {
        offset += snprintf(cmd+offset, 2048-offset, "%02x", input->coord2[i]);
    }
    offset += snprintf(cmd+offset, 2048-offset, "';\n");

    JS_Eval(ctx, cmd, strlen(cmd), "<none>", JS_EVAL_TYPE_GLOBAL);
    fuzzec_js_aux(input, output, genjsadd, genjsadd_size);
}
