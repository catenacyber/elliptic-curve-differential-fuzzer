cmake_minimum_required (VERSION 2.8)

#Golang
project (ecfuzzer CXX C)
set(ECFUZZER_MAJOR_VERSION 0)
set(ECFUZZER_MINOR_VERSION 1)
set(ECFUZZER_MICRO_VERSION 0)
set(ECFUZZER_VERSION ${ECFUZZER_MAJOR_VERSION}.${ECFUZZER_MINOR_VERSION}.${ECFUZZER_MICRO_VERSION})

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -DDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall -DDEBUG")
add_definitions(-DWITH_STDLIB)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

#does not work : set(GLOBAL PROPERTY FIND_LIBRARY_USE_LIB32_PATHS TRUE)
set (CMAKE_LIBRARY_PATH ${CMAKE_LIBRARY_PATH};/usr/local/lib32/)
find_library(MBEDCRYPTO_LIB mbedcrypto)
find_library(LIBECC_LIB ec)
find_library(OPENSSL_LIB crypto)
find_library(NETTLE0_LIB libgmp.a gmp)
find_library(NETTLE1_LIB libhogweed.a hogweed)
find_library(NETTLE2_LIB libnettle.a nettle)
find_library(GCRYPT_LIB gcrypt)
find_library(GPGERROR_LIB gpg-error)
find_library(CRYPTOPP_LIB cryptopp)
find_library(BOTAN_LIB botan-2)
find_library(QUICKJS_LIB quickjs)

include_directories(/usr/local/include/botan-2/)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_custom_command(
    OUTPUT goelliptic.a
    COMMAND go build -o goelliptic.a -buildmode=c-archive ${CMAKE_CURRENT_SOURCE_DIR}/modules/elliptic.go
    COMMAND cp goelliptic.h ${CMAKE_CURRENT_SOURCE_DIR}/
    DEPENDS modules/elliptic.go
    COMMENT "Build c archive out of golang"
)

add_custom_target(goelliptic_target DEPENDS goelliptic.a)

add_library(goelliptic STATIC IMPORTED GLOBAL)
add_dependencies(goelliptic goelliptic_target)

set_target_properties(goelliptic
    PROPERTIES
    IMPORTED_LOCATION goelliptic.a
)

add_custom_command(
    OUTPUT genjsinit.h
    COMMAND browserify ${CMAKE_CURRENT_SOURCE_DIR}/modules/ecinit.js --bare -o bundle.js
    COMMAND qjsc -c -N genjsinit -o genjsinit.h bundle.js
    DEPENDS modules/ecinit.js
    COMMENT "Build c init out of javascript"
)

add_custom_command(
    OUTPUT genjsmult.h
    COMMAND qjsc -c -N genjsmult -o genjsmult.h ${CMAKE_CURRENT_SOURCE_DIR}/modules/ecmult.js 
    DEPENDS modules/ecmult.js
    COMMENT "Build c mult out of javascript"
)

add_custom_command(
    OUTPUT genjsadd.h
    COMMAND qjsc -c -N genjsadd -o genjsadd.h ${CMAKE_CURRENT_SOURCE_DIR}/modules/ecadd.js 
    DEPENDS modules/ecadd.js
    COMMENT "Build c add out of javascript"
)

option(DISABLE_CRYPTOPP "disable cryptopp module" OFF)
if(DISABLE_CRYPTOPP)
	add_definitions(-DFUZZ_CRYPTOPP_DISABLED)
endif()

set(ecfuzzer_src fuzz_ec.c modules/mbedtls.c modules/libecc.c modules/openssl.c modules/nettle.c modules/gcrypt.c modules/cryptopp.cpp modules/botan.cpp modules/golang.c modules/script.c genjsinit.h genjsmult.h genjsadd.h)
set(ecfuzzer_libs "${MBEDCRYPTO_LIB}" "${LIBECC_LIB}" "${OPENSSL_LIB}" "${NETTLE1_LIB}" "${NETTLE2_LIB}" "${NETTLE0_LIB}" "${GCRYPT_LIB}" "${GPGERROR_LIB}" "${CRYPTOPP_LIB}" "${BOTAN_LIB}" "${QUICKJS_LIB}" goelliptic)
IF(DEFINED ENV{LIB_FUZZING_ENGINE})
	set(ecfuzzer_libs ${ecfuzzer_libs} $ENV{LIB_FUZZING_ENGINE})
else()
	set(ecfuzzer_src ${ecfuzzer_src} main.c)
endif()

add_executable (ecfuzzer ${ecfuzzer_src})
target_link_libraries (ecfuzzer ${ecfuzzer_libs})

