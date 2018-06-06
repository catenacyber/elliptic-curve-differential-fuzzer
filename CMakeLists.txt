cmake_minimum_required (VERSION 2.8)

project (ecfuzzer C)
set(ECFUZZER_MAJOR_VERSION 0)
set(ECFUZZER_MINOR_VERSION 1)
set(ECFUZZER_MICRO_VERSION 0)
set(ECFUZZER_VERSION ${ECFUZZER_MAJOR_VERSION}.${ECFUZZER_MINOR_VERSION}.${ECFUZZER_MICRO_VERSION})

add_definitions(-DWITH_STDLIB)

find_library(MBEDCRYPTO_LIB mbedcrypto)
find_library(LIBECC_LIB ec)
find_library(OPENSSL_LIB crypto)

add_executable (ecfuzzer main.c fuzz_ec.c modules/mbedtls.c modules/libecc.c modules/openssl.c)
target_link_libraries (ecfuzzer "${MBEDCRYPTO_LIB}" "${LIBECC_LIB}" "${OPENSSL_LIB}")
