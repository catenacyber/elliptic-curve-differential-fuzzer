cmake_minimum_required (VERSION 2.8)

project (ecfuzzer C)
set(ECFUZZER_MAJOR_VERSION 0)
set(ECFUZZER_MINOR_VERSION 1)
set(ECFUZZER_MICRO_VERSION 0)
set(ECFUZZER_VERSION ${ECFUZZER_MAJOR_VERSION}.${ECFUZZER_MINOR_VERSION}.${ECFUZZER_MICRO_VERSION})

add_definitions(-D	WITH_STDLIB)

find_library(MBEDCRYPTO_LIB mbedcrypto)
find_library(LIBECC_LIB ec)

add_executable (ecfuzzer main.c fuzz_ec.c mbedtls.c libecc.c)
target_link_libraries (ecfuzzer "${MBEDCRYPTO_LIB}" "${LIBECC_LIB}")
