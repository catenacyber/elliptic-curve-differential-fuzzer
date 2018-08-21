cmake_minimum_required (VERSION 2.8)

project (ecfuzzer C CXX)
set(ECFUZZER_MAJOR_VERSION 0)
set(ECFUZZER_MINOR_VERSION 1)
set(ECFUZZER_MICRO_VERSION 0)
set(ECFUZZER_VERSION ${ECFUZZER_MAJOR_VERSION}.${ECFUZZER_MINOR_VERSION}.${ECFUZZER_MICRO_VERSION})

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -DDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall -DDEBUG")
add_definitions(-DWITH_STDLIB)

find_library(MBEDCRYPTO_LIB mbedcrypto)
find_library(LIBECC_LIB ec)
find_library(OPENSSL_LIB crypto)
find_library(NETTLE0_LIB gmp)
find_library(NETTLE1_LIB hogweed)
find_library(NETTLE2_LIB nettle)
find_library(GCRYPT_LIB gcrypt)
find_library(CRYPTOPP_LIB cryptopp)

add_executable (ecfuzzer main.c fuzz_ec.c modules/mbedtls.c modules/libecc.c modules/openssl.c modules/nettle.c modules/gcrypt.c modules/cryptopp.cpp)
target_link_libraries (ecfuzzer "${MBEDCRYPTO_LIB}" "${LIBECC_LIB}" "${OPENSSL_LIB}" "${NETTLE0_LIB}" "${NETTLE1_LIB}" "${NETTLE2_LIB}" "${GCRYPT_LIB}" "${CRYPTOPP_LIB}")
