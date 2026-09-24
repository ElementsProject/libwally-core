idf_component_register(SRCS main.c wally_amalgamation.c INCLUDE_DIRS . PRIV_REQUIRES mbedtls)
get_filename_component(WALLY "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)
# The empty config.h in this directory must be found before ${WALLY}/src/config.h
target_include_directories(${COMPONENT_LIB} PRIVATE ${WALLY} ${WALLY}/src ${WALLY}/src/ccan ${WALLY}/src/secp256k1/include ${WALLY}/include)
# Mirrors the definitions used by Jade's libwally-core component
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    HAVE_PSA_CRYPTO_H=1 BUILD_ELEMENTS=1 BUILD_MINIMAL=1 HAVE_EXPLICIT_BZERO=1 HAVE_BUILTIN_POPCOUNT=1
    ENABLE_MODULE_ECDH=1 ENABLE_MODULE_RECOVERY=1 ENABLE_MODULE_SCHNORRSIG=1 ENABLE_MODULE_EXTRAKEYS=1
    ENABLE_MODULE_GENERATOR=1 ENABLE_MODULE_RANGEPROOF=1 ENABLE_MODULE_SURJECTIONPROOF=1
    ENABLE_MODULE_WHITELIST=1 ENABLE_MODULE_ECDSA_S2C=1 ECMULT_WINDOW_SIZE=8)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-nonnull-compare -Wno-unused-function
    -Wno-error=maybe-uninitialized -Wno-type-limits -Wno-error=array-parameter -Wno-unused-parameter)
