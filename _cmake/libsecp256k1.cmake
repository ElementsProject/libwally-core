
include(ExternalProject)
include(GNUInstallDirs)

find_program(MAKE_EXE NAMES gmake nmake make)

set(_secp_enable_tests --disable-tests)
if(ENABLE_TESTS)
    set(_secp_enable_tests --enable-tests)
endif()
set(_secp_with_asm --with-asm=no)
if(ENABLE_ASM AND NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(_secp_with_asm --with-asm=yes)
endif()

set(_secp_lib_type STATIC)
set(_secp_lib_type_option --disable-shared)
if(BUILD_SHARED_LIBS)
    set(_secp_lib_type SHARED)
    set(_secp_lib_type_option --enable-shared)
endif()

set(_secp_host_build_config "")
if(CMAKE_CROSSCOMPILING)
    if(NOT CONFIGURE_AC_HOST)
        message(FATAL_ERROR "when cross-building, please define CONFIGURE_AC_HOST to be passed to libsecp256k1 as --host=<CONFIGURE_AC_HOST>")
    endif()
    if(NOT CONFIGURE_AC_BUILD)
        message(FATAL_ERROR "when cross-building, please define CONFIGURE_AC_BUILD to be passed to libsecp256k1 as --build=<CONFIGURE_AC_BUILD>")
    endif()
    set(_secp_host_build_config "--host=${CONFIGURE_AC_HOST} --build=${CONFIGURE_AC_BUILD}")
endif()

if(CMAKE_BUILD_TYPE)
    string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE_UC)
endif()


ExternalProject_Add(libsecp256k1-build
    DOWNLOAD_COMMAND ""
    SOURCE_DIR ${CMAKE_SOURCE_DIR}/src/secp256k1
    CONFIGURE_COMMAND <SOURCE_DIR>/configure
        "CC=${CMAKE_C_COMPILER}"
        "AR=${CMAKE_AR}"
        "RANLIB=${CMAKE_C_COMPILER_RANLIB}"
        "CFLAGS=${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${BUILD_TYPE_UC}}"
        "LDFLAGS=${CMAKE_${_secp_lib_type}_LINKER_FLAGS} ${CMAKE_${_secp_lib_type}_LINKER_FLAGS_${BUILD_TYPE_UC}}"
        --prefix <INSTALL_DIR>
        ${_secp_lib_type_option}
        --with-pic
        --with-bignum=no
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
        --enable-openssl-tests=no
        --enable-exhaustive-tests=no
        --enable-benchmark=no
        --disable-dependency-tracking
        ${_secp_enable_tests}
        ${_secp_with_asm}
        ${_secp_host_build_config}

    BUILD_COMMAND ${MAKE_EXE}

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


install(
    FILES $<TARGET_PROPERTY:libsecp256k1,IMPORTED_LOCATION>
    DESTINATION ${CMAKE_INSTALL_LIBDIR}
    COMPONENT libsecp256k1
)
install(
    FILES $<TARGET_PROPERTY:libsecp256k1,PUBLIC_HEADER>
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    COMPONENT libsecp256k1
)
install(
    FILES ${INSTALL_DIR}/lib/pkgconfig/libsecp256k1.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
    COMPONENT libsecp256k1
)
install(SCRIPT ${CMAKE_SOURCE_DIR}/cmake/libsecp256k1-pkgconfig.cmake
    COMPONENT libsecp256k1
)
