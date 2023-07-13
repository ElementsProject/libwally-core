
include(ExternalProject)

find_program(MAKE_EXE NAMES gmake nmake make)

if(ENABLE_ASM AND NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    list(APPEND _secp_options "--with-asm=yes")
else()
    list(APPEND _secp_options "--with-asm=no")
endif()

if(CMAKE_CROSSCOMPILING)
    if(NOT CONFIGURE_AC_HOST)
        message(FATAL_ERROR "when cross-building, please define CONFIGURE_AC_HOST to be passed to libsecp256k1 as --host=<CONFIGURE_AC_HOST>")
    endif()
    if(NOT CONFIGURE_AC_BUILD)
        message(FATAL_ERROR "when cross-building, please define CONFIGURE_AC_BUILD to be passed to libsecp256k1 as --build=<CONFIGURE_AC_BUILD>")
    endif()
    list(APPEND _secp_options "--host=${CONFIGURE_AC_HOST}" "--build=${CONFIGURE_AC_BUILD}")
endif()

if(CMAKE_BUILD_TYPE)
    string(TOUPPER ${CMAKE_BUILD_TYPE} cmake_build_type_upcase)
endif()


ExternalProject_Add(libsecp256k1-build
    SOURCE_DIR ${CMAKE_SOURCE_DIR}/src/secp256k1
    BUILD_IN_SOURCE True
    CONFIGURE_COMMAND <SOURCE_DIR>/configure
        "CC=${CMAKE_C_COMPILER}"
        "AR=${CMAKE_AR}"
        "RANLIB=${CMAKE_C_COMPILER_RANLIB}"
        "CFLAGS=${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${cmake_build_type_upcase}}"
        "LDFLAGS=${CMAKE_${_secp_lib_type}_LINKER_FLAGS} ${CMAKE_${_secp_lib_type}_LINKER_FLAGS_${cmake_build_type_upcase}}"
        --prefix <INSTALL_DIR>
        --enable-static
        --disable-tests
        --with-pic
        --enable-experimental
        --enable-module-ecdh
        --enable-module-recovery
        --enable-module-ecdsa-s2c
        --enable-module-rangeproof
        --enable-module-surjectionproof
        --enable-module-whitelist
        --enable-module-generator
        --enable-module-extrakeys
        --enable-module-schnorrsig
        --enable-exhaustive-tests=no
        --enable-benchmark=no
        --disable-dependency-tracking
        ${_secp_options}

    BUILD_COMMAND ${MAKE_EXE}
    BUILD_BYPRODUCTS <INSTALL_DIR>/lib/libsecp256k1.a

    INSTALL_COMMAND ${MAKE_EXE} install
)


ExternalProject_Get_Property(libsecp256k1-build INSTALL_DIR)

add_library(libsecp256k1 STATIC IMPORTED)
set(_secp_public_headers
    ${INSTALL_DIR}/include/secp256k1_ecdh.h
    ${INSTALL_DIR}/include/secp256k1_ecdsa_s2c.h
    ${INSTALL_DIR}/include/secp256k1_extrakeys.h
    ${INSTALL_DIR}/include/secp256k1_generator.h
    ${INSTALL_DIR}/include/secp256k1.h
    ${INSTALL_DIR}/include/secp256k1_preallocated.h
    ${INSTALL_DIR}/include/secp256k1_rangeproof.h
    ${INSTALL_DIR}/include/secp256k1_recovery.h
    ${INSTALL_DIR}/include/secp256k1_schnorrsig.h
    ${INSTALL_DIR}/include/secp256k1_surjectionproof.h
    ${INSTALL_DIR}/include/secp256k1_whitelist.h
)
set_target_properties(libsecp256k1 PROPERTIES
    IMPORTED_LOCATION ${INSTALL_DIR}/lib/libsecp256k1.a
    PUBLIC_HEADER "${_secp_public_headers}"
)
add_dependencies(libsecp256k1 libsecp256k1-build)
