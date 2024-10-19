file(
    GLOB ccan_srcs
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    "ccan/ccan/base64/*.[ch]"
    "ccan/ccan/build_assert/*.h"
    "ccan/ccan/compiler/*.h"
    "ccan/ccan/crypto/sha256/*.[ch]"
    "ccan/ccan/crypto/sha512/*.[ch]"
    "ccan/ccan/crypto/ripemd160/*.[ch]"
    "ccan/ccan/endian/*.h"
    "ccan/ccan/str/hex/*.[ch]"
    "ccan/ccan/tap/*.[ch]"
)
file(
    GLOB wallycore_srcs
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    "*.[ch]"
)
list(REMOVE_ITEM ccan_srcs ccan/ccan/crypto/sha256/sha256_sse4.c)
message("ccan_srcs: ${ccan_srcs}")
file(
    GLOB wallycore_public_headers
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    "${CMAKE_SOURCE_DIR}/include/*.h"
)

# wallycore
add_library(wallycore STATIC)
target_sources(wallycore PRIVATE ${ccan_srcs} ${wallycore_srcs})
set_target_properties(wallycore PROPERTIES PUBLIC_HEADER "${wallycore_public_headers}")
target_include_directories(
    wallycore
    PUBLIC $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}> $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include> $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE ${CMAKE_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/ccan
)
target_link_libraries(wallycore PUBLIC secp256k1)
if(WALLYCORE_ENABLE_COVERAGE AND CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(wallycore PRIVATE --coverage)
    target_link_options(wallycore PUBLIC --coverage)
endif()

if (WALLYCORE_BUILD_ELEMENTS)
    target_compile_definitions(wallycore PRIVATE BUILD_ELEMENTS)
endif()

if(NOT WALLYCORE_INSTALL)
    return()
endif()

# install directives
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(LIB_CMAKE_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/wallycore)

configure_package_config_file(
    ${CMAKE_SOURCE_DIR}/cmake/wallycore-config.cmake.in "${CMAKE_CURRENT_BINARY_DIR}/wallycore-config.cmake"
    INSTALL_DESTINATION ${LIB_CMAKE_INSTALL_DIR}
    PATH_VARS LIB_CMAKE_INSTALL_DIR
)
write_basic_package_version_file(
    wallycore-config-version.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/wallycore-config.cmake"
              "${CMAKE_CURRENT_BINARY_DIR}/wallycore-config-version.cmake" DESTINATION ${LIB_CMAKE_INSTALL_DIR}
)
install(
    TARGETS wallycore
    EXPORT "wallycore-target"
    COMPONENT wallycore
    RUNTIME EXCLUDE_FROM_ALL
    OBJECTS EXCLUDE_FROM_ALL
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(
    EXPORT "wallycore-target"
    DESTINATION ${LIB_CMAKE_INSTALL_DIR}
    NAMESPACE wallycore::
    FILE "wallycore-targets.cmake"
)
