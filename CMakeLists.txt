cmake_minimum_required(VERSION 3.13)

# AC_INIT([libwallycore],[0.7.4])
set(PACKAGE_VERSION   0.7.4)
# AC_INIT([libsecp256k1],[0.1])
set(WALLY_PACKAGE_VERSION   \"${PACKAGE_VERSION}\")
set(SECP256K1_PACKAGE_VERSION   \"0.1\")

# wally project
cmake_policy(SET CMP0076 NEW)
cmake_policy(SET CMP0086 NEW)
set(CMAKE_VERBOSE_MAKEFILE TRUE)

####################
# options
####################
include(./cmake/EnableCcache.cmake)

if(CMAKE_JS_INC)
option(ENABLE_SHARED "enable shared library (ON or OFF. default:ON)" ON)
else()
option(ENABLE_SHARED "enable shared library (ON or OFF. default:OFF)" OFF)
endif()
# use "cmake -DCMAKE_BUILD_TYPE=Debug" or "cmake-js -D"
# option(ENABLE_DEBUG "enable debugging (ON or OFF. default:OFF)" OFF)
option(ENABLE_ELEMENTS "enable elements tx code (ON or OFF. default:OFF)" OFF)
option(ENABLE_SWIG_PYTHON "enable the SWIG python interface (ON or OFF. default:OFF)" OFF)
option(ENABLE_SWIG_GO "enable the SWIG Go interface (ON or OFF. default:OFF)" OFF)
option(GENERATE_WALLY "generate the wally.xxx library (ON or OFF. default:ON)" ON)
option(ENABLE_EMSCRIPTEN "enable EMSCRIPTEN (ON or OFF. default:OFF)" OFF)
option(ENABLE_SECP256K1_TEST "enable secp256k1 test (ON or OFF. default:OFF)" OFF)

if(NOT EXCLUDE_GENERATE_WALLY)
set(EXCLUDE_GENERATE_WALLY  FALSE)
endif()

if(CMAKE_JS_INC)
option(ENABLE_JS_WRAPPER "enable the Javascript interface wrappers (ON or OFF. default:ON)" ON)
else()
set(ENABLE_JS_WRAPPER off)
endif()
option(ENABLE_TESTS "enable code tests for CTest (ON or OFF. default:ON)" ON)

if(NOT WIN32)
option(ENABLE_SWIG_JAVA "enable the SWIG java (JNI) interface (ON or OFF. default:OFF)" OFF)
#option(TARGET_RPATH "target rpath list (separator is ';') (default:)" "")
set(TARGET_RPATH "" CACHE STRING "target rpath list (separator is ';') (default:)")
option(ENABLE_COVERAGE "enable code coverage (ON or OFF. default:OFF)" OFF)
option(ENABLE_EXPORT_ALL "enable export all functions (for testing) (ON or OFF. default:OFF)" OFF)
option(ENABLE_RPATH "enable rpath (ON or OFF. default:ON)" ON)
else()
set(ENABLE_SWIG_JAVA off)
set(TARGET_RPATH off)
set(ENABLE_COVERAGE off)
set(ENABLE_EXPORT_ALL off)
set(ENABLE_RPATH off)
endif()

if(ENABLE_EXPORT_ALL)
set(ENABLE_EXPORT_ALL_OPT -fvisibility=hidden)
else()
set(ENABLE_EXPORT_ALL_OPT "")
endif()

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
set(ENABLE_DEBUG  TRUE)
set(RPATH_TARGET  "Debug")
set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS $<$<CONFIG:Debug>:DEBUGBUILD>)
else()
set(ENABLE_DEBUG  FALSE)
set(RPATH_TARGET  "Release")
endif() # CMAKE_BUILD_TYPE

####################
# common setting
####################
include(./cmake/WallyCoverage.cmake)

# WALLY_BINARY_DIR_ROOT
set(WORK_WINDOWS_BINARY_DIR_NAME  $<IF:$<CONFIG:Debug>,Debug,Release>)
if(NOT WALLY_OBJ_BINARY_DIR)
set(WALLY_OBJ_BINARY_DIR    ${CMAKE_BINARY_DIR}/${WORK_WINDOWS_BINARY_DIR_NAME})
set(WALLY_ROOT_BINARY_DIR   ${CMAKE_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY  ${WALLY_OBJ_BINARY_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY  ${WALLY_OBJ_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY  ${WALLY_OBJ_BINARY_DIR}) # for linux
message(STATUS "[libwally] WALLY_OBJ_BINARY_DIR=${WALLY_OBJ_BINARY_DIR}")
endif()

if(NOT ENABLE_ELEMENTS)
set(ELEMENTS_COMP_OPT "")
set(ELEMENTS_SWIG_DEFINE "")
else()
set(ELEMENTS_COMP_OPT  BUILD_ELEMENTS)
set(ELEMENTS_SWIG_DEFINE -DBUILD_ELEMENTS)
endif()

if(NOT WIN32)
if(ENABLE_RPATH)
set(CMAKE_SKIP_BUILD_RPATH  FALSE)
if(APPLE)
set(CMAKE_MACOSX_RPATH 1)
else()
set(CMAKE_BUILD_RPATH_USE_ORIGIN TRUE)
endif()
set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

if(TARGET_RPATH)
if(APPLE)
string(REPLACE "\$\$ORIGIN" "." TEMP_RPATH1 "${TARGET_RPATH}")
string(REPLACE "\$ORIGIN" "." TEMP_RPATH2 "${TEMP_RPATH1}")
string(REPLACE "\$\${ORIGIN}" "." TEMP_RPATH3 "${TEMP_RPATH2}")
string(REPLACE "\${ORIGIN}" "." MODIFIED_RPATH "${TEMP_RPATH3}")
set(CMAKE_INSTALL_RPATH "${MODIFIED_RPATH};./;./build/${RPATH_TARGET};./wallycore;@rpath")
else()
string(REPLACE "\$\${ORIGIN}" "$$ORIGIN" TEMP_RPATH1 "${TARGET_RPATH}")
string(REPLACE "\${ORIGIN}" "$ORIGIN" MODIFIED_RPATH "${TEMP_RPATH1}")
set(CMAKE_INSTALL_RPATH "${MODIFIED_RPATH};$ORIGIN/;./;./build/${RPATH_TARGET};./wallycore;@rpath")
endif()
else(TARGET_RPATH)
if(APPLE)
set(CMAKE_INSTALL_RPATH "./;./build/${RPATH_TARGET};./wallycore;@rpath")
else()
set(CMAKE_INSTALL_RPATH "$ORIGIN/;./;./build/${RPATH_TARGET};./wallycore;@rpath")
endif()
endif(TARGET_RPATH) 
# message(STATUS "CMAKE_INSTALL_RPATH is => ${CMAKE_INSTALL_RPATH}")

else()
set(CMAKE_SKIP_BUILD_RPATH  TRUE)
endif()
endif()

if(ENABLE_EMSCRIPTEN)
set(WALLY_EMSCRIPTEN "WALLY_EMSCRIPTEN")
else()
set(WALLY_EMSCRIPTEN "")
endif()

####################
# wally common setting
####################
if(PYTHONHOME)
set(INCLUDE_PYTHONHOME  ${PYTHONHOME}/include)
else()
set(INCLUDE_PYTHONHOME  "")
endif()


####################
# config.h & libsecp256k1-config.h
####################
project(wally_config C CXX)
set(CONFIG_HEADER_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

if(MSVC)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /Od /Zi")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /Od /Zi")
else()
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -ggdb")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -ggdb")
endif()

# incomplete
include(CheckFunctionExists)
include(CheckSymbolExists)
include(CheckIncludeFile)
include(TestBigEndian)
include(CheckCSourceCompiles)
include(CheckCXXSourceCompiles)

if(APPLE)
set(AC_APPLE_UNIVERSAL_BUILD "1")
endif()

if(MSVC)  # force active
set(HAVE_MMAP     "1")
set(HAVE_UNISTD_H "1")
set(HAVE_PTHREAD "1")
set(HAVE_PTHREAD_PRIO_INHERIT "1")
set(HAVE_LIBCRYPTO "1")

else()
# not windows
check_function_exists(memset_s HAVE_MEMSET_S)
check_function_exists(explicit_bzero HAVE_EXPLICIT_BZERO)
check_function_exists(explicit_memset HAVE_EXPLICIT_MEMSET)
check_function_exists(memset_s HAVE_MEMSET_S)
check_function_exists(mmap HAVE_MMAP)
check_cxx_source_compiles("int main() { __builtin_clzll(0); return 0; }"
  HAVE_BUILTIN_CLZLL)

set(HAVE___INT128  "1")
check_include_file("unistd.h" HAVE_UNISTD_H)

find_package(LIBCRYPTO QUIET)
if(LIBCRYPTO_FOUND)
set(HAVE_LIBCRYPTO "1")
else()
check_include_file("openssl/crypto.h" HAVE_OPENSSL_CRYPTO_H)
if(HAVE_OPENSSL_CRYPTO_H)
set(HAVE_LIBCRYPTO "1")
endif(HAVE_OPENSSL_CRYPTO_H)
endif()

find_package(Threads QUIET)
if(Threads_FOUND)
set(HAVE_PTHREAD "1")
set(HAVE_PTHREAD_PRIO_INHERIT "1")
endif()

endif()
# PTHREAD_CREATE_JOINABLE

if(${PYTHON})
set(HAVE_PYTHON \"${PYTHON}\")
endif()

CHECK_SYMBOL_EXISTS(posix_memalign stdlib.h HAVE_POSIX_MEMALIGN)
check_c_source_compiles("extern int foo(int) __attribute__((weak)); int main(void){return foo(0);}"
  HAVE_ATTRIBUTE_WEAK)
check_c_source_compiles("int main(void){static int a[2];return *((int*)(((char*)a)+1)) != 0;}"
  HAVE_UNALIGNED_ACCESS)
check_c_source_compiles("int main(void){int a = 42; int *pnt = &a; __asm__ __volatile__ (\"\" : : \"r\"(pnt) : \"memory\"); return 0;}"
  HAVE_INLINE_ASM)

set(STDC_HEADERS  "1")
check_include_file("asm/page.h" HAVE_ASM_PAGE_H)
check_include_file("byteswap.h" HAVE_BYTESWAP_H_)
check_include_file("memory.h" HAVE_MEMORY_H)
check_include_file("stdint.h" HAVE_STDINT_H)
check_include_file("stdlib.h" HAVE_STDLIB_H)
check_include_file("strings.h" HAVE_STRINGS_H)
check_include_file("string.h" HAVE_STRING_H)
check_include_file("sys/mman.h" HAVE_SYS_MMAN_H)
check_include_file("sys/stat.h" HAVE_SYS_STAT_H)
check_include_file("sys/types.h" HAVE_SYS_TYPES_H)
check_include_file("dlfcn.h" HAVE_DLFCN_H)
check_include_file("inttypes.h" HAVE_INTTYPES_H)

if(NOT WIN32)
TEST_BIG_ENDIAN(WORDS_BIGENDIAN)
endif()

foreach(inline_keyword "inline" "__inline__" "__inline")
  if(NOT DEFINED C_INLINE)
    set(CMAKE_REQUIRED_DEFINITIONS_SAVE ${CMAKE_REQUIRED_DEFINITIONS})
    set(CMAKE_REQUIRED_DEFINITIONS ${CMAKE_REQUIRED_DEFINITIONS}
        "-Dinline=${inline_keyword}")
    check_c_source_compiles("
        typedef int foo_t;
        static inline foo_t static_foo() {return 0;}
        foo_t foo(){return 0;}
        int main(int argc, char *argv[]) {return 0;}"
      C_HAS_${inline_keyword})
  endif()
endforeach()

if((NOT C_HAS_inline) AND (C_HAS___inline__ OR C_HAS___inline))
if(C_HAS___inline__)
set(inline  ${C_HAS___inline__})
else()
set(inline  ${C_HAS___inline})
endif()
endif()

if(NOT ENABLE_EMSCRIPTEN)
check_type_size(size_t SIZEOF_SIZE_T LANGUAGE C)
if(NOT HAVE_SIZEOF_SIZE_T)
if(${CMAKE_SIZEOF_VOID_P} EQUAL 8)
set(size_t "uint64_t")
else()
set(size_t "uint32_t")
endif()
endif()

check_type_size(ssize_t SIZEOF_SSIZE_T LANGUAGE C)
if(NOT HAVE_SIZEOF_SSIZE_T)
if(${CMAKE_SIZEOF_VOID_P} EQUAL 8)
set(ssize_t "int64_t")
else()
set(ssize_t "int32_t")
endif()
endif()
endif(NOT ENABLE_EMSCRIPTEN)

# secp256k1 configure options
# ac_configure_args="${ac_configure_args} --disable-shared ${secp_jni} --with-pic --with-bignum=no --enable-experimental --enable-module-ecdh --enable-module-recovery --enable-module-rangeproof --enable-module-surjectionproof --enable-module-whitelist --enable-module-generator --enable-openssl-tests=no --enable-tests=no --enable-exhaustive-tests=no --enable-benchmark=no --disable-dependency-tracking"

# USE_ENDOMORPHISM (option only)
set(ECMULT_WINDOW_SIZE "15")
set(ENABLE_MODULE_ECDH "1")
set(ENABLE_MODULE_RECOVERY "1")
set(ENABLE_MODULE_RANGEPROOF "1")
set(ENABLE_MODULE_SURJECTIONPROOF "1")
set(ENABLE_MODULE_WHITELIST "1")
set(ENABLE_MODULE_GENERATOR "1")
set(ENABLE_MODULE_SCHNORRSIG "1")
set(ENABLE_MODULE_MUSIG "1")
set(ENABLE_MODULE_EXTRAKEYS "1")
set(ENABLE_MODULE_ECDSA_ADAPTOR "1")

check_cxx_source_compiles("int main() { __builtin_popcount(0); return 0;}"
  HAVE_BUILTIN_POPCOUNT)

if(ARMCC)
set(USE_EXTERNAL_ASM "1")
else()
set(USE_ASM_X86_64 "1")
endif()
set(USE_ECMULT_STATIC_PRECOMPUTATION "1")
# set(USE_REDUCED_SURJECTION_PROOF_SIZE "1")

find_package(GMP QUIET)
if(GMP_FOUND)
set(USE_NUM_GMP "1")
set(USE_FIELD_INV_NUM  "1")
set(USE_SCALAR_INV_NUM "1")
set(HAVE_LIBGMP "1")
else()
set(USE_NUM_NONE "1")
set(USE_FIELD_INV_BUILTIN  "1")
set(USE_SCALAR_INV_BUILTIN "1")
endif()

if(WIN32)
set(USE_FIELD_10X26 "1")
set(USE_SCALAR_8X32 "1")
elseif("${CMAKE_SIZEOF_VOID_P}" STREQUAL "4")
# x86
set(USE_FIELD_10X26 "1")
set(USE_SCALAR_8X32 "1")
else()
# x64
set(USE_FIELD_5X52  "1")
set(USE_SCALAR_4X64 "1")
endif()

set(VERSION   WALLY_PACKAGE_VERSION)
configure_file(cmake/config.h.in              "${CONFIG_HEADER_DIRECTORY}/config.h")
configure_file(cmake/libsecp256k1-config.h.in "${CONFIG_HEADER_DIRECTORY}/libsecp256k1-config.h")


####################
# secp256k1/gen_context
####################
project(secp256k1 C)
set(GEN_CONTEXT_NAME gen_context)

set(SECP256K_OUTPUT_PATH  ${CMAKE_CURRENT_BINARY_DIR})

if(WIN32 OR XCODE)
set(GEN_CONTEXT_PATH ${WALLY_OBJ_BINARY_DIR}/${GEN_CONTEXT_NAME})
else()
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY  ${CMAKE_CURRENT_BINARY_DIR})
set(GEN_CONTEXT_PATH ${SECP256K_OUTPUT_PATH}/${GEN_CONTEXT_NAME})
endif()

set(SRC_WALLY_CONFIG_H  ${CMAKE_CURRENT_SOURCE_DIR}/src/config.h)
set(SRC_SECP256K1_CONFIG_H  ${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1/src/libsecp256k1-config.h)
set(ECMULT_STATIC_CONTEXT_H  ${CMAKE_CURRENT_BINARY_DIR}/ecmult_static_context.h)
set(SRC_ECMULT_STATIC_CONTEXT_H  ${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1/src/ecmult_static_context.h)
add_executable(${GEN_CONTEXT_NAME}
    src/secp256k1/src/gen_context.c
    ${CONFIG_HEADER_DIRECTORY}/config.h
    ${CONFIG_HEADER_DIRECTORY}/libsecp256k1-config.h
)

target_compile_options(${GEN_CONTEXT_NAME}
  PRIVATE
    $<IF:$<C_COMPILER_ID:MSVC>,
      /source-charset:utf-8 /wd4244,
      -Wall -Wextra -Wno-unused-function
    >
)
target_compile_definitions(${GEN_CONTEXT_NAME}
  PRIVATE
    WALLY_CORE_BUILD
    SECP256K1_BUILD
)
target_include_directories(${GEN_CONTEXT_NAME}
  PRIVATE
    src/secp256k1/include
    ${CONFIG_HEADER_DIRECTORY}
    src/secp256k1
    src/secp256k1/src
    src/secp256k1/contrib
)

set(SECP256K1_GEN_CONTEXT_NAME secp256k1_gen_context)
add_custom_target(${SECP256K1_GEN_CONTEXT_NAME}
  SOURCES ${ECMULT_STATIC_CONTEXT_H}
)

if(ENABLE_EMSCRIPTEN)
set(CMAKE_ECMULT_STATIC_CONTEXT_H  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/ecmult_static_context.h)

if(${CMAKE_VERSION} VERSION_LESS "3.17.0")
add_custom_command(OUTPUT  ${ECMULT_STATIC_CONTEXT_H}
  COMMAND echo "[gen_context] copy from " ${CMAKE_ECMULT_STATIC_CONTEXT_H}
  COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_ECMULT_STATIC_CONTEXT_H} ${ECMULT_STATIC_CONTEXT_H}
  COMMAND ${CMAKE_COMMAND} -E remove -f ${SRC_SECP256K1_CONFIG_H}
  COMMAND ${CMAKE_COMMAND} -E remove -f ${SRC_WALLY_CONFIG_H}
  DEPENDS ${GEN_CONTEXT_NAME}
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1
  VERBATIM
)
else()
add_custom_command(OUTPUT  ${ECMULT_STATIC_CONTEXT_H}
  COMMAND echo "[gen_context] copy from " ${CMAKE_ECMULT_STATIC_CONTEXT_H}
  COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_ECMULT_STATIC_CONTEXT_H} ${ECMULT_STATIC_CONTEXT_H}
  COMMAND ${CMAKE_COMMAND} -E rm -f ${SRC_SECP256K1_CONFIG_H}
  COMMAND ${CMAKE_COMMAND} -E rm -f ${SRC_WALLY_CONFIG_H}
  DEPENDS ${GEN_CONTEXT_NAME}
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1
  VERBATIM
)
endif()

else(ENABLE_EMSCRIPTEN)

if(${CMAKE_VERSION} VERSION_LESS "3.17.0")
add_custom_command(OUTPUT  ${ECMULT_STATIC_CONTEXT_H}
  COMMAND echo "[gen_context]" ${GEN_CONTEXT_PATH}
  COMMAND ${GEN_CONTEXT_PATH}
  COMMAND ${CMAKE_COMMAND} -E copy_if_different ${SRC_ECMULT_STATIC_CONTEXT_H} ${ECMULT_STATIC_CONTEXT_H}
  COMMAND ${CMAKE_COMMAND} -E compare_files ${SRC_ECMULT_STATIC_CONTEXT_H} ${ECMULT_STATIC_CONTEXT_H}
  COMMAND ${CMAKE_COMMAND} -E remove -f ${SRC_ECMULT_STATIC_CONTEXT_H}
  COMMAND ${CMAKE_COMMAND} -E remove -f ${SRC_SECP256K1_CONFIG_H}
  COMMAND ${CMAKE_COMMAND} -E remove -f ${SRC_WALLY_CONFIG_H}
  DEPENDS ${GEN_CONTEXT_NAME}
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1
  VERBATIM
)
else()
add_custom_command(OUTPUT  ${ECMULT_STATIC_CONTEXT_H}
  COMMAND echo "[gen_context]" ${GEN_CONTEXT_PATH}
  COMMAND ${GEN_CONTEXT_PATH}
  COMMAND ${CMAKE_COMMAND} -E copy_if_different ${SRC_ECMULT_STATIC_CONTEXT_H} ${ECMULT_STATIC_CONTEXT_H}
  COMMAND ${CMAKE_COMMAND} -E compare_files ${SRC_ECMULT_STATIC_CONTEXT_H} ${ECMULT_STATIC_CONTEXT_H}
  COMMAND ${CMAKE_COMMAND} -E rm -f ${SRC_ECMULT_STATIC_CONTEXT_H}
  COMMAND ${CMAKE_COMMAND} -E rm -f ${SRC_SECP256K1_CONFIG_H}
  COMMAND ${CMAKE_COMMAND} -E rm -f ${SRC_WALLY_CONFIG_H}
  DEPENDS ${GEN_CONTEXT_NAME}
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1
  VERBATIM
)
endif()
endif(ENABLE_EMSCRIPTEN)


####################
# libwally sources
####################
set(LIBWALLY_FILES
    ${CONFIG_HEADER_DIRECTORY}/config.h
    ${CONFIG_HEADER_DIRECTORY}/libsecp256k1-config.h
    src/address.c
    src/aes.c
    src/base58.c
    src/bip32.c
    src/bip38.c
    src/bip39.c
    src/bech32.c
    src/blech32.c
    src/descriptor.c
    src/elements.c
    src/ecdh.c
    src/hex.c
    src/hmac.c
    src/internal.c
    src/mnemonic.c
    src/pbkdf2.c
    src/psbt.c
    src/script.c
    src/scrypt.c
    src/sign.c
    src/transaction.c
    src/wif.c
    src/wordlist.c
    src/symmetric.c
    src/ccan/ccan/crypto/ripemd160/ripemd160.c
    src/ccan/ccan/crypto/sha256/sha256.c
    src/ccan/ccan/crypto/sha512/sha512.c
    src/ccan/ccan/str/hex/hex.c
    src/ccan/ccan/base64/base64.c
    src/ccan/ccan/base64/base64.h
    src/secp256k1/src/secp256k1.c
    include/wally.hpp
    include/wally_address.h
    include/wally_bip32.h
    include/wally_bip38.h
    include/wally_bip39.h
    include/wally_core.h
    include/wally_crypto.h
    include/wally_descriptor.h
    include/wally_elements.h
    include/wally_script.h
    include/wally_transaction.h
    include/wally_symmetric.h
    include/wally_psbt.h
    src/secp256k1/include/secp256k1.h
    src/secp256k1/include/secp256k1_recovery.h
    src/bip32_int.h
    src/script_int.h
    src/transaction_int.h
    src/transaction_shared.h
    ${ECMULT_STATIC_CONTEXT_H}
)

####################
# libwally
####################
if(EXCLUDE_GENERATE_WALLY)
set(GENERATE_WALLY_LIB FALSE)
elseif((NOT GENERATE_WALLY) OR (NOT ${GENERATE_WALLY}))
set(GENERATE_WALLY_LIB FALSE)
elseif(ENABLE_SWIG_JAVA)
set(GENERATE_WALLY_LIB FALSE)
#elseif(ENABLE_JS_WRAPPER)
#set(GENERATE_WALLY_LIB FALSE)
else()
set(GENERATE_WALLY_LIB TRUE)
endif()

if(GENERATE_WALLY_LIB)
project(wally C)
set(WALLY_PROJECT_NAME wally)
set(WALLYCORE_NAME wally)

if(ENABLE_SHARED)
add_library(${PROJECT_NAME} SHARED)
else()
add_library(${PROJECT_NAME} STATIC)
endif()
target_sources(${PROJECT_NAME}
  PRIVATE
    ${LIBWALLY_FILES}
)

#add_dependencies(${PROJECT_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1/src/ecmult_static_context.h)
#    src/secp256k1/src/ecmult_static_context.h
target_compile_options(${PROJECT_NAME}
  PRIVATE
    $<IF:$<C_COMPILER_ID:MSVC>,
      /LD /source-charset:utf-8 /wd4244,
      -Wall -Wextra -Wno-unused-function
      ${PROFILE_ARCS_OPT} ${TEST_COVERAGE_OPT} ${ENABLE_EXPORT_ALL_OPT}
    >
)
target_compile_definitions(${PROJECT_NAME}
  PRIVATE
    ${ELEMENTS_COMP_OPT}
    WALLY_CORE_BUILD
    SECP256K1_BUILD
    HAVE_CONFIG_H
    ${WALLY_EMSCRIPTEN}
)
# -DECMULT_WINDOW_SIZE=16 -DUSE_ECMULT_STATIC_PRECOMPUTATION
target_include_directories(${PROJECT_NAME}
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1/include>
    $<INSTALL_INTERFACE:include>
  PRIVATE
    ${CONFIG_HEADER_DIRECTORY}
    .
    src
    src/ccan
    src/secp256k1
    src/secp256k1/src
    ${SECP256K_OUTPUT_PATH}
)

if(COLLECT_COVERAGE)
target_link_libraries(${PROJECT_NAME} ${GCOV_LIBRARY})
endif()

endif() # GENERATE_WALLY OR (ENABLE_JS_WRAPPER)


####################
# node.js build
####################
if(ENABLE_JS_WRAPPER)

set(INSTALL_WALLYCORE  FALSE)
set(NODE_LIBRARY_NAME wallycore)
project(wallycore CXX)

find_package(Python3 COMPONENTS Interpreter)
find_package(PythonInterp REQUIRED)
if(Python3_Interpreter_FOUND)
set(PYTHON_BIN  ${Python3_EXECUTABLE})
message(STATUS "python is 3(${Python3_VERSION})")
else()
set(PYTHON_BIN  ${PYTHON_EXECUTABLE})
message(STATUS "python version is ${PYTHON_VERSION_STRING}")
endif()

if(ENABLE_ELEMENTS)
set(ELEMENTS_OPT "elements")
else()
set(ELEMENTS_OPT "")
endif()
set(OUTPUT_DIR_NAME $<IF:$<CONFIG:Debug>,Debug,Release>)

message(STATUS "[libwally] NODE_RUNTIME=${NODE_RUNTIME}")
message(STATUS "[libwally] NODE_RUNTIMEVERSION=${NODE_RUNTIMEVERSION}")
message(STATUS "[libwally] CMAKE_JS_LIB=${CMAKE_JS_LIB}")
message(STATUS "[libwally] CMAKE_JS_SRC=${CMAKE_JS_SRC}")
set(NODEJS_WRAP_CC_NAME nodejs_wrap_cc)
add_custom_target(${NODEJS_WRAP_CC_NAME} SOURCES ${CMAKE_CURRENT_BINARY_DIR}/nodejs_wrap.cc)

set(NODE_TEST_SRC_DIR       ${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/test)
set(NODE_TEST_DATA_SRC_DIR  ${CMAKE_CURRENT_SOURCE_DIR}/src/data)
set(NODE_TEST_BASE_DIR      ${CMAKE_CURRENT_BINARY_DIR}/test_wrap_js)
set(NODE_TEST_JS_DIR        ${NODE_TEST_BASE_DIR}/wrap_js)
set(NODE_TEST_DATA_DIR      ${NODE_TEST_BASE_DIR}/data)
set(NODE_TEST_FILE_DIR      ${NODE_TEST_JS_DIR}/test)
set(NODE_TEST_BUILD_DIR     ${NODE_TEST_JS_DIR}/build)
set(NODE_TEST_RELEASE_DIR   ${NODE_TEST_JS_DIR}/build/${WORK_WINDOWS_BINARY_DIR_NAME})

# generate source files, and create test directories
if(${CMAKE_VERSION} VERSION_LESS "3.17.0")
add_custom_command(OUTPUT  ${CMAKE_CURRENT_BINARY_DIR}/nodejs_wrap.cc
  COMMAND set PYTHONDONTWRITEBYTECODE=1
  COMMAND cd ${CMAKE_CURRENT_SOURCE_DIR}/src
  COMMAND ${PYTHON_BIN} ${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/makewrappers/wrap.py nodejs ${OUTPUT_DIR_NAME} ${ELEMENTS_OPT}
  COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/nodejs_wrap.cc" ${CMAKE_CURRENT_BINARY_DIR}/nodejs_wrap.cc
  COMMAND ${CMAKE_COMMAND} -E remove -f "${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/nodejs_wrap.cc"
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src
  VERBATIM
)
else()
add_custom_command(OUTPUT  ${CMAKE_CURRENT_BINARY_DIR}/nodejs_wrap.cc
  COMMAND set PYTHONDONTWRITEBYTECODE=1
  COMMAND cd ${CMAKE_CURRENT_SOURCE_DIR}/src
  COMMAND ${PYTHON_BIN} ${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/makewrappers/wrap.py nodejs ${OUTPUT_DIR_NAME} ${ELEMENTS_OPT}
  COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/nodejs_wrap.cc" ${CMAKE_CURRENT_BINARY_DIR}/nodejs_wrap.cc
  COMMAND ${CMAKE_COMMAND} -E rm -f "${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/nodejs_wrap.cc"
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src
  VERBATIM
)
endif()

set(CMAKE_CXX_STANDARD 11)
add_library(${NODE_LIBRARY_NAME} SHARED)
target_sources(${NODE_LIBRARY_NAME}
  PRIVATE
    ${LIBWALLY_FILES}
    ${CMAKE_CURRENT_BINARY_DIR}/nodejs_wrap.cc
    ${CMAKE_JS_SRC}
)
if(GENERATE_WALLY_LIB)
add_dependencies(${WALLY_PROJECT_NAME} ${NODE_LIBRARY_NAME})
endif()

target_compile_options(${NODE_LIBRARY_NAME}
  PRIVATE
    $<IF:$<C_COMPILER_ID:MSVC>,
      /LD /source-charset:utf-8 /wd4244 /wd4251,
      -Wall -Wextra -Wno-unused-function
      ${ENABLE_EXPORT_ALL_OPT}
    >
)
target_compile_definitions(${NODE_LIBRARY_NAME}
  PRIVATE
    ${ELEMENTS_COMP_OPT}
    DWALLY_CORE_BUILD
    HAVE_CONFIG_H
    SECP256K1_BUILD
    SWIG_JAVASCRIPT_BUILD
)

set_target_properties(${NODE_LIBRARY_NAME} PROPERTIES PREFIX "" SUFFIX ".node")

# Include N-API wrappers
#execute_process(COMMAND node -p "require('node-addon-api').include"
#    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
#    OUTPUT_VARIABLE NODE_ADDON_API_DIR
#)
#string(REPLACE "\"" "" NODE_ADDON_API_DIR ${NODE_ADDON_API_DIR})
# target_include_directories( PRIVATE ${NODE_ADDON_API_DIR} )
target_include_directories(${NODE_LIBRARY_NAME}
  PRIVATE
    include
    src/secp256k1/include
    ${CONFIG_HEADER_DIRECTORY}
    .
    src
    src/ccan
    src/secp256k1
    src/secp256k1/src
    ${SECP256K_OUTPUT_PATH}
    node_modules/nan
    ${CMAKE_JS_INC}
)

target_link_libraries(${NODE_LIBRARY_NAME}
  PRIVATE $<$<BOOL:$<CXX_COMPILER_ID:MSVC>>:winmm.lib>
  PRIVATE $<$<BOOL:$<CXX_COMPILER_ID:MSVC>>:ws2_32.lib>
  PRIVATE $<$<BOOL:$<CXX_COMPILER_ID:GNU>>:-static-libgcc>
  PRIVATE $<$<BOOL:$<CXX_COMPILER_ID:GNU>>:-static-libstdc++>
  PRIVATE $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:pthread>
  PRIVATE $<IF:$<OR:$<PLATFORM_ID:Darwin>,$<PLATFORM_ID:Windows>>,,rt>
  PRIVATE
    ${CMAKE_JS_LIB}
)

if(${CMAKE_VERSION} VERSION_LESS "3.17.0")
add_custom_command(
    TARGET ${NODE_LIBRARY_NAME}
    POST_BUILD
    COMMAND set PYTHONDONTWRITEBYTECODE=1
    COMMAND ${PYTHON_BIN} ${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/makewrappers/wrap.py wally ${OUTPUT_DIR_NAME} ${ELEMENTS_OPT}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/wally.js ${CMAKE_CURRENT_BINARY_DIR}/wally.js
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/wally.js ${WALLY_OBJ_BINARY_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/wally.js ${CMAKE_BINARY_DIR}/..
    COMMAND ${CMAKE_COMMAND} -E make_directory ${NODE_TEST_BASE_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${NODE_TEST_JS_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${NODE_TEST_FILE_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${NODE_TEST_JS_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${NODE_TEST_JS_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${NODE_TEST_BUILD_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${NODE_TEST_RELEASE_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${NODE_TEST_DATA_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${NODE_TEST_DATA_SRC_DIR} ${NODE_TEST_DATA_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/wally.js ${NODE_TEST_JS_DIR}
    COMMAND ${CMAKE_COMMAND} -E remove -f ${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/wally.js
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src
)
else()
add_custom_command(
    TARGET ${NODE_LIBRARY_NAME}
    POST_BUILD
    COMMAND set PYTHONDONTWRITEBYTECODE=1
    COMMAND ${PYTHON_BIN} ${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/makewrappers/wrap.py wally ${OUTPUT_DIR_NAME} ${ELEMENTS_OPT}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/wally.js ${CMAKE_CURRENT_BINARY_DIR}/wally.js
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/wally.js ${WALLY_OBJ_BINARY_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/wally.js ${CMAKE_BINARY_DIR}/..
    COMMAND ${CMAKE_COMMAND} -E make_directory ${NODE_TEST_BASE_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${NODE_TEST_JS_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${NODE_TEST_FILE_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${NODE_TEST_JS_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${NODE_TEST_JS_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${NODE_TEST_BUILD_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${NODE_TEST_RELEASE_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${NODE_TEST_DATA_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${NODE_TEST_DATA_SRC_DIR} ${NODE_TEST_DATA_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/wally.js ${NODE_TEST_JS_DIR}
    COMMAND ${CMAKE_COMMAND} -E rm -f ${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/wally.js
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src
)
endif()

elseif(ENABLE_SWIG_JAVA)
# after build
set(WALLYCORE_NAME wallycore)
set(INSTALL_WALLYCORE  FALSE)

else()	# ENABLE_JS_WRAPPER

####################
# libwally library
####################
set(WALLYCORE_NAME wallycore)
set(WALLY_PROJECT_NAME ${WALLYCORE_NAME})
set(INSTALL_WALLYCORE  TRUE)

if(ENABLE_SHARED)
add_library(${WALLYCORE_NAME} SHARED)
else()
add_library(${WALLYCORE_NAME} STATIC)
endif()
if(WIN32)
set_target_properties(${WALLYCORE_NAME} PROPERTIES PREFIX "lib" SUFFIX ".dll")
endif()
target_sources(${WALLYCORE_NAME}
  PRIVATE
    ${LIBWALLY_FILES}
)

#add_dependencies(${WALLYCORE_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1/src/ecmult_static_context.h)

#    src/secp256k1/src/ecmult_static_context.h
target_compile_options(${WALLYCORE_NAME}
  PRIVATE
    $<IF:$<C_COMPILER_ID:MSVC>,
      /LD /source-charset:utf-8 /wd4244,
      -Wall -Wextra -Wno-unused-function
      ${PROFILE_ARCS_OPT} ${TEST_COVERAGE_OPT} ${ENABLE_EXPORT_ALL_OPT}
    >
)
target_compile_definitions(${WALLYCORE_NAME}
  PRIVATE
    ${ELEMENTS_COMP_OPT}
    WALLY_CORE_BUILD
    SECP256K1_BUILD
    HAVE_CONFIG_H
    ${WALLY_EMSCRIPTEN}
)
target_include_directories(${WALLYCORE_NAME}
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1/include>
    $<INSTALL_INTERFACE:include>
  PRIVATE
    ${CONFIG_HEADER_DIRECTORY}
    .
    src
    src/ccan
    src/secp256k1
    src/secp256k1/src
    ${SECP256K_OUTPUT_PATH}
)

if(COLLECT_COVERAGE)
target_link_libraries(${WALLYCORE_NAME} ${GCOV_LIBRARY})
endif()

if(GENERATE_WALLY_LIB)
add_dependencies(${PROJECT_NAME} ${WALLYCORE_NAME})
endif()

endif()		# ENABLE_JS_WRAPPER


####################
# swig python
####################
# swig proto (Generation of __init__.py not implemented)
if(ENABLE_SWIG_PYTHON)
# -module <module_name>SWIG SWIG_MODULE_NAME
# -module wallycore SWIG

# PYTHON_SWIGTEST
# set(ENV{PYTHONDONTWRITEBYTECODE} 1)
# set(ENV{PYTHONPATH} ".libs:swig_python")

set(WALLY_SWIG_PYTHON_NAME wallycore_swig_python)
set(WALLY_SWIG_PYTHON_OUTPUT_NAME wallycore)
project(${WALLY_SWIG_PYTHON_NAME} C)
set(PYTHON_WALLY_FILE ${CMAKE_CURRENT_BINARY_DIR}/wallycore.py)

set_property(SOURCE src/swig_python/swig.i PROPERTY SWIG_MODULE_NAME wallycore)
set(PY_INTERFACE_FILE  src/swig_python/swig.i)

find_package(PythonLibs REQUIRED)
find_package(SWIG REQUIRED)

include(${SWIG_USE_FILE})
include(GenerateExportHeader)
include_directories(${PYTHON_INCLUDE_DIRS})
message(STATUS "[PythonLibs version] ${PYTHONLIBS_VERSION_STRING}")

if(NOT INCLUDE_PYTHONHOME)
set(INCLUDE_PYTHONHOME  ${PYTHON_INCLUDE_DIRS})
endif()

# swig_python_wrap.c
swig_add_library(${WALLY_SWIG_PYTHON_NAME}
    TYPE SHARED
    LANGUAGE python
    OUTFILE_DIR ${CMAKE_CURRENT_BINARY_DIR}
    SOURCES ${PY_INTERFACE_FILE} ${LIBWALLY_FILES}
)

if(PYTHONHOME)
set_property(TARGET ${WALLY_SWIG_PYTHON_NAME} PROPERTY SWIG_INCLUDE_DIRECTORIES 
    ${PYTHONHOME}/include
)
include_directories(
    ${PYTHONHOME}/include
)
endif()
# set full path.
set_property(TARGET ${WALLY_SWIG_PYTHON_NAME} PROPERTY SWIG_INCLUDE_DIRECTORIES 
    ${CONFIG_HEADER_DIRECTORY}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ccan
    ${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1
    ${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1/src
    ${SECP256K_OUTPUT_PATH}
    ${SWIG_PATH}/Lib/python
    ${CMAKE_CURRENT_SOURCE_DIR}/src/swig_python
    ${INCLUDE_PYTHONHOME}
)
target_include_directories(${WALLY_SWIG_PYTHON_NAME}
  PRIVATE
    ${CONFIG_HEADER_DIRECTORY}
    include
    .
    src
    src/ccan
    src/secp256k1
    src/secp256k1/src
    ${SECP256K_OUTPUT_PATH}
    ${SWIG_PATH}/Lib/python
    src/swig_python
    ${INCLUDE_PYTHONHOME}
)

# SWIG_INCLUDE_DIRECTORIES
set_property(TARGET ${WALLY_SWIG_PYTHON_NAME} PROPERTY SWIG_COMPILE_DEFINITIONS 
    SWIG_PYTHON_BUILD WALLY_CORE_BUILD SECP256K1_BUILD USE_ECMULT_STATIC_PRECOMPUTATION HAVE_CONFIG_H ${ELEMENTS_COMP_OPT}
)
set_property(TARGET ${WALLY_SWIG_PYTHON_NAME} PROPERTY SWIG_COMPILE_OPTIONS 
    -DSWIG_PYTHON_BUILD -DWALLY_CORE_BUILD -DSECP256K1_BUILD -DHAVE_CONFIG_H ${ELEMENTS_SWIG_DEFINE}
)
# swig_link_libraries(${WALLY_SWIG_PYTHON_NAME} ${PYTHON_LIBRARIES} wally)
target_link_libraries(${WALLY_SWIG_PYTHON_NAME}
  PRIVATE $<$<BOOL:$<C_COMPILER_ID:GCC>>:-static-libgcc> ${PYTHON_LIBRARIES})

target_compile_options(${WALLY_SWIG_PYTHON_NAME}
  PRIVATE
    $<IF:$<C_COMPILER_ID:MSVC>,
      /LD /source-charset:utf-8 /wd4244 /I"${INCLUDE_PYTHONHOME}",
      -Wall -Wextra -Wno-unused-function
    >
)
target_compile_definitions(${WALLY_SWIG_PYTHON_NAME}
  PRIVATE
    ${ELEMENTS_COMP_OPT}
    WALLY_CORE_BUILD
    SECP256K1_BUILD
    HAVE_CONFIG_H
    SWIG_PYTHON_BUILD
)
set_target_properties(${WALLY_SWIG_PYTHON_NAME} PROPERTIES OUTPUT_NAME ${WALLY_SWIG_PYTHON_OUTPUT_NAME})

# %SWIG_PATH%\swig -python -Isrc -I%SWIG_PATH%\Lib\python -DBUILD_ELEMENTS=1 src\swig_python\swig.i
# copy src\swig_python\wallycore.py + src\swig_python\python_extra.py_in src\swig_python\wallycore\__init__.py /B
# del src\swig_python\wallycore.py

#     $(GNU_SED) -i 's/_wallycore/libwallycore/g' swig_python/wallycore.py $@ && \
#     cat swig_python/wallycore.py swig_python/python_extra.py_in > swig_python/wallycore/__init__.py && \

set(SWIG_PY_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src/swig_python)
set(SWIG_PY_OUTPUT_DIR ${WALLY_ROOT_BINARY_DIR}/swig_python)
set(GEN_PYTHON_FILE    ${SWIG_PY_SOURCE_DIR}/python_extra.py_in)

if(${CMAKE_VERSION} VERSION_LESS "3.17.0")
if(WIN32)
add_custom_target(swig_python_cmd  ALL
    COMMAND echo "[generate python file]"
    COMMAND ${CMAKE_COMMAND} -E copy ${PYTHON_WALLY_FILE} wallycore.py
    COMMAND ${CMAKE_COMMAND} -E copy ${GEN_PYTHON_FILE} python_extra.py_in
    COMMAND echo "copy /Y /B ${PYTHON_WALLY_FILE} + ${GEN_PYTHON_FILE}  __init__.py /B"
    COMMAND COPY /Y /B wallycore.py + python_extra.py_in __init__.py /B
    COMMAND ${CMAKE_COMMAND} -E remove -f wallycore.py
    COMMAND ${CMAKE_COMMAND} -E remove -f python_extra.py_in
    COMMAND ${CMAKE_COMMAND} -E make_directory ${SWIG_PY_OUTPUT_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${SWIG_PY_OUTPUT_DIR}/wallycore
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${SWIG_PY_SOURCE_DIR} ${SWIG_PY_OUTPUT_DIR}
    COMMAND ${CMAKE_COMMAND} -E remove -f ${SWIG_PY_OUTPUT_DIR}/swig.i
    COMMAND ${CMAKE_COMMAND} -E remove -f ${SWIG_PY_OUTPUT_DIR}/python_extra.py_in
    COMMAND ${CMAKE_COMMAND} -E copy __init__.py ${SWIG_PY_OUTPUT_DIR}/wallycore/__init__.py
    COMMAND ${CMAKE_COMMAND} -E remove -f __init__.py
    COMMAND ${CMAKE_COMMAND} -E copy ${WALLY_OBJ_BINARY_DIR}/_${WALLY_SWIG_PYTHON_OUTPUT_NAME}.pyd ${SWIG_PY_OUTPUT_DIR}/wallycore/_${WALLY_SWIG_PYTHON_OUTPUT_NAME}.pyd
    DEPENDS ${WALLY_SWIG_PYTHON_NAME}
    VERBATIM
    USES_TERMINAL
)
else()
set(SWIG_PY_OUTPUT_FILE  _${WALLY_SWIG_PYTHON_OUTPUT_NAME}.so)
add_custom_target(swig_python_cmd  ALL
    COMMAND echo "[generate python file]"
    COMMAND ${CMAKE_COMMAND} -E copy ${PYTHON_WALLY_FILE} wallycore.py
    COMMAND ${CMAKE_COMMAND} -E copy ${GEN_PYTHON_FILE} python_extra.py_in
    COMMAND echo "cat wallycore.py > __init__.py && cat python_extra.py_in >> __init__.py"
    COMMAND cat wallycore.py > __init__.py
    COMMAND cat python_extra.py_in >> __init__.py
    COMMAND ${CMAKE_COMMAND} -E remove -f wallycore.py
    COMMAND ${CMAKE_COMMAND} -E remove -f python_extra.py_in
    COMMAND ${CMAKE_COMMAND} -E make_directory ${SWIG_PY_OUTPUT_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${SWIG_PY_OUTPUT_DIR}/wallycore
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${SWIG_PY_SOURCE_DIR} ${SWIG_PY_OUTPUT_DIR}
    COMMAND ${CMAKE_COMMAND} -E remove -f ${SWIG_PY_OUTPUT_DIR}/swig.i
    COMMAND ${CMAKE_COMMAND} -E remove -f ${SWIG_PY_OUTPUT_DIR}/python_extra.py_in
    COMMAND ${CMAKE_COMMAND} -E copy __init__.py ${SWIG_PY_OUTPUT_DIR}/wallycore/__init__.py
    COMMAND ${CMAKE_COMMAND} -E remove -f __init__.py
    COMMAND ${CMAKE_COMMAND} -E copy ${WALLY_OBJ_BINARY_DIR}/${SWIG_PY_OUTPUT_FILE} ${SWIG_PY_OUTPUT_DIR}/wallycore/${SWIG_PY_OUTPUT_FILE}
    # for test
    COMMAND ${CMAKE_COMMAND} -E copy ${WALLY_OBJ_BINARY_DIR}/${SWIG_PY_OUTPUT_FILE} ${SWIG_PY_OUTPUT_DIR}/contrib/${SWIG_PY_OUTPUT_FILE}
    DEPENDS ${WALLY_SWIG_PYTHON_NAME}
    VERBATIM
    USES_TERMINAL
)
endif()
else(${CMAKE_VERSION} VERSION_LESS "3.17.0")
if(WIN32)
add_custom_target(swig_python_cmd  ALL
    COMMAND echo "[generate python file]"
    COMMAND ${CMAKE_COMMAND} -E copy ${PYTHON_WALLY_FILE} wallycore.py
    COMMAND ${CMAKE_COMMAND} -E copy ${GEN_PYTHON_FILE} python_extra.py_in
    COMMAND echo "copy /Y /B ${PYTHON_WALLY_FILE} + ${GEN_PYTHON_FILE}  __init__.py /B"
    COMMAND COPY /Y /B wallycore.py + python_extra.py_in __init__.py /B
    COMMAND ${CMAKE_COMMAND} -E rm -f wallycore.py
    COMMAND ${CMAKE_COMMAND} -E rm -f python_extra.py_in
    COMMAND ${CMAKE_COMMAND} -E make_directory ${SWIG_PY_OUTPUT_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${SWIG_PY_OUTPUT_DIR}/wallycore
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${SWIG_PY_SOURCE_DIR} ${SWIG_PY_OUTPUT_DIR}
    COMMAND ${CMAKE_COMMAND} -E rm -f ${SWIG_PY_OUTPUT_DIR}/swig.i
    COMMAND ${CMAKE_COMMAND} -E rm -f ${SWIG_PY_OUTPUT_DIR}/python_extra.py_in
    COMMAND ${CMAKE_COMMAND} -E copy __init__.py ${SWIG_PY_OUTPUT_DIR}/wallycore/__init__.py
    COMMAND ${CMAKE_COMMAND} -E rm -f __init__.py
    COMMAND ${CMAKE_COMMAND} -E copy ${WALLY_OBJ_BINARY_DIR}/_${WALLY_SWIG_PYTHON_OUTPUT_NAME}.pyd ${SWIG_PY_OUTPUT_DIR}/wallycore/_${WALLY_SWIG_PYTHON_OUTPUT_NAME}.pyd
    DEPENDS ${WALLY_SWIG_PYTHON_NAME}
    VERBATIM
    USES_TERMINAL
)
else()
set(SWIG_PY_OUTPUT_FILE  _${WALLY_SWIG_PYTHON_OUTPUT_NAME}.so)
add_custom_target(swig_python_cmd  ALL
    COMMAND echo "[generate python file]"
    COMMAND ${CMAKE_COMMAND} -E copy ${PYTHON_WALLY_FILE} wallycore.py
    COMMAND ${CMAKE_COMMAND} -E copy ${GEN_PYTHON_FILE} python_extra.py_in
    COMMAND echo "cat wallycore.py > __init__.py && cat python_extra.py_in >> __init__.py"
    COMMAND cat wallycore.py > __init__.py
    COMMAND cat python_extra.py_in >> __init__.py
    COMMAND ${CMAKE_COMMAND} -E rm -f wallycore.py
    COMMAND ${CMAKE_COMMAND} -E rm -f python_extra.py_in
    COMMAND ${CMAKE_COMMAND} -E make_directory ${SWIG_PY_OUTPUT_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${SWIG_PY_OUTPUT_DIR}/wallycore
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${SWIG_PY_SOURCE_DIR} ${SWIG_PY_OUTPUT_DIR}
    COMMAND ${CMAKE_COMMAND} -E rm -f ${SWIG_PY_OUTPUT_DIR}/swig.i
    COMMAND ${CMAKE_COMMAND} -E rm -f ${SWIG_PY_OUTPUT_DIR}/python_extra.py_in
    COMMAND ${CMAKE_COMMAND} -E copy __init__.py ${SWIG_PY_OUTPUT_DIR}/wallycore/__init__.py
    COMMAND ${CMAKE_COMMAND} -E rm -f __init__.py
    COMMAND ${CMAKE_COMMAND} -E copy ${WALLY_OBJ_BINARY_DIR}/${SWIG_PY_OUTPUT_FILE} ${SWIG_PY_OUTPUT_DIR}/wallycore/${SWIG_PY_OUTPUT_FILE}
    # for test
    COMMAND ${CMAKE_COMMAND} -E copy ${WALLY_OBJ_BINARY_DIR}/${SWIG_PY_OUTPUT_FILE} ${SWIG_PY_OUTPUT_DIR}/contrib/${SWIG_PY_OUTPUT_FILE}
    DEPENDS ${WALLY_SWIG_PYTHON_NAME}
    VERBATIM
    USES_TERMINAL
)
endif()
endif(${CMAKE_VERSION} VERSION_LESS "3.17.0")

# if IS_OSX
# # Python requires the shared library have a .so extension for 'import'
# .libs/libwallycore.so:
# 	$(AM_V_at)ln -s libwallycore.dylib .libs/libwallycore.so
# SWIG_PYTHON_TEST_DEPS = .libs/libwallycore.so
# endif

# noinst_LTLIBRARIES += libswig_python.la
# libswig_python_la_CFLAGS = -I$(top_srcdir) $(AM_CFLAGS) $(SWIG_PYTHON_CPPFLAGS) $(SWIG_WARN_CFLAGS) $(NOALIAS_CFLAGS)
# libswig_python_la_LIBADD = $(PYTHON_LIBS)

endif()		# ENABLE_SWIG_PYTHON


####################
# swig java
####################
if(ENABLE_SWIG_JAVA)

find_package(JNI REQUIRED)
find_package(Java REQUIRED)
find_package(SWIG REQUIRED)

include(${SWIG_USE_FILE})
include(UseJava)
include(GenerateExportHeader)
set(JAVAC_TARGET  1.8)

set(SECP256K1_JNI_FILES
    src/secp256k1/src/java/org_bitcoin_NativeSecp256k1.c
    src/secp256k1/src/java/org_bitcoin_Secp256k1Context.c
    src/secp256k1/src/java/org_bitcoin_NativeSecp256k1.h
    src/secp256k1/src/java/org_bitcoin_Secp256k1Context.h
    src/secp256k1/include/secp256k1_ecdh.h
    src/secp256k1/include/secp256k1_recovery.h
)

set(WALLY_SWIG_JAVA_NAME wallycore_swig_java)
set(WALLY_PROJECT_NAME ${WALLY_SWIG_JAVA_NAME})
set(WALLY_SWIG_JAVA_OUTPUT_NAME wallycore)
set(WALLYCORE_NAME wallycore)
project(${WALLY_SWIG_JAVA_NAME} C)

set_property(SOURCE src/swig_java/swig.i PROPERTY SWIG_MODULE_NAME wallycore)
set(SWIG_JAVA_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src/swig_java)
set(SWIG_JAVA_OUTPUT_DIR ${WALLY_ROOT_BINARY_DIR}/swig_java)
set(SWIG_JAVA_PACKAGE_DIR ${SWIG_JAVA_OUTPUT_DIR}/src/com/blockstream/libwally)
set(GEN_JAVA_FILE    ${SWIG_JAVA_SOURCE_DIR}/jni_extra.java_in)
set(OUT_JAVA_FILE    ${CMAKE_CURRENT_BINARY_DIR}/swigJAVA_wrap.c)
set(JAVA_INTERFACE_FILE  ${SWIG_JAVA_SOURCE_DIR}/swig_gen.i)

# change to "%module (jniclassname="name") modulename"
add_custom_command(OUTPUT ${JAVA_INTERFACE_FILE}
  COMMAND ${CMAKE_COMMAND} -E copy ${SWIG_JAVA_SOURCE_DIR}/swig.i ${JAVA_INTERFACE_FILE}
  # https://www.linuxquestions.org/questions/linux-newbie-8/sed-gives-sed-e-expression-1-char-1-unknown-command-%60%27%27-947056/
  COMMAND sed -i "s/ wallycore/ (jniclassname=\"Wally\") wallycore/" ${JAVA_INTERFACE_FILE}
#  COMMAND sed -i 's/ = (char \*) (\*jenv)\->Get/ = (unsigned char \*) (\*jenv)\->Get/g' ${JAVA_INTERFACE_FILE}
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src
  VERBATIM
)

set(CMAKE_SWIG_FLAGS  -package com.blockstream.libwally)
if(ENABLE_SHARED)
swig_add_library(${WALLY_SWIG_JAVA_NAME}
    TYPE SHARED
    LANGUAGE java
    NO_PROXY
    OUTFILE_DIR ${CMAKE_CURRENT_BINARY_DIR}
    SOURCES ${JAVA_INTERFACE_FILE} ${LIBWALLY_FILES} ${SECP256K1_JNI_FILES})
else()
swig_add_library(${WALLY_SWIG_JAVA_NAME}
    TYPE STATIC
    LANGUAGE java
    NO_PROXY
    OUTFILE_DIR ${CMAKE_CURRENT_BINARY_DIR}
    SOURCES ${JAVA_INTERFACE_FILE} ${LIBWALLY_FILES} ${SECP256K1_JNI_FILES})
endif()

# message (STATUS "JNI_INCLUDE_DIRS=${JNI_INCLUDE_DIRS}")
# message (STATUS "JNI_LIBRARIES=${JNI_LIBRARIES}")
include_directories(${JNI_INCLUDE_DIRS})
set_property(TARGET ${WALLY_SWIG_JAVA_NAME} PROPERTY SWIG_INCLUDE_DIRECTORIES 
    ${JNI_INCLUDE_DIRS}
)
# set full path.
set_property(TARGET ${WALLY_SWIG_JAVA_NAME} PROPERTY SWIG_INCLUDE_DIRECTORIES 
    ${CONFIG_HEADER_DIRECTORY}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ccan
    ${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1
    ${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1/src/java
    ${SECP256K_OUTPUT_PATH}
    ${SWIG_PATH}/Lib/java
    ${CMAKE_CURRENT_SOURCE_DIR}/src/swig_java
    ${JNI_INCLUDE_DIRS}
)
target_include_directories(${WALLY_SWIG_JAVA_NAME}
  PUBLIC
    include
    src/secp256k1/include
  PRIVATE
    ${CONFIG_HEADER_DIRECTORY}
    .
    src
    src/ccan
    src/secp256k1
    src/secp256k1/src
    src/secp256k1/src/java
    ${SECP256K_OUTPUT_PATH}
    src/swig_java
    ${JNI_INCLUDE_DIRS}
)

# SWIG_INCLUDE_DIRECTORIES
set_property(TARGET ${WALLY_SWIG_JAVA_NAME} PROPERTY SWIG_COMPILE_DEFINITIONS 
    SWIG_JAVA_BUILD WALLY_CORE_BUILD SECP256K1_BUILD USE_ECMULT_STATIC_PRECOMPUTATION HAVE_CONFIG_H ${ELEMENTS_COMP_OPT}
)
set_property(TARGET ${WALLY_SWIG_JAVA_NAME} PROPERTY SWIG_COMPILE_OPTIONS 
    -DSWIG_JAVA_BUILD -DWALLY_CORE_BUILD -DSECP256K1_BUILD -DHAVE_CONFIG_H ${ELEMENTS_SWIG_DEFINE}
)
# swig_link_libraries(${WALLY_SWIG_JAVA_NAME} ${JNI_LIBRARIES} wally)
target_link_libraries(${WALLY_SWIG_JAVA_NAME}
  PRIVATE $<$<BOOL:$<C_COMPILER_ID:GCC>>:-static-libgcc> ${JNI_LIBRARIES})

target_compile_options(${WALLY_SWIG_JAVA_NAME}
  PRIVATE
    $<IF:$<C_COMPILER_ID:MSVC>,
      /LD /source-charset:utf-8 /wd4244 /DWALLY_CORE_BUILD /DHAVE_CONFIG_H /DSECP256K1_BUILD /DSWIG_JAVA_BUILD /I"${JNI_INCLUDE_DIRS}" ${ELEMENTS_COMP_OPT},
      -Wall -Wextra -Wno-unused-function
    >
)
target_compile_definitions(${WALLY_SWIG_JAVA_NAME}
  PRIVATE
    ${ELEMENTS_COMP_OPT}
    WALLY_CORE_BUILD
    SECP256K1_BUILD
    HAVE_CONFIG_H
    SWIG_JAVA_BUILD
)
set_target_properties(${WALLY_SWIG_JAVA_NAME} PROPERTIES OUTPUT_NAME ${WALLY_SWIG_JAVA_OUTPUT_NAME})
if(${CMAKE_VERSION} VERSION_LESS "3.17.0")
add_custom_command(
    TARGET ${WALLY_SWIG_JAVA_NAME}
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E remove -f ${JAVA_INTERFACE_FILE}
    COMMAND ${CMAKE_COMMAND} -E copy  ${CMAKE_CURRENT_BINARY_DIR}/Wally.java ${SWIG_JAVA_SOURCE_DIR}/wallycoreJNI.java
    COMMAND ${CMAKE_COMMAND} -E copy  ${CMAKE_CURRENT_BINARY_DIR}/wallycoreConstants.java ${SWIG_JAVA_SOURCE_DIR}/wallycoreConstants.java
#    COMMAND sed -i 's/ = (char \*) (\*jenv)\->Get/ = (unsigned char \*) (\*jenv)\->Get/g' ${OUT_JAVA_FILE}
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tools/swigjavapost.sh sed ${ELEMENTS_COMP_OPT}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${SWIG_JAVA_OUTPUT_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${SWIG_JAVA_SOURCE_DIR}/src ${SWIG_JAVA_OUTPUT_DIR}/src
    COMMAND ${CMAKE_COMMAND} -E remove -f ${SWIG_JAVA_SOURCE_DIR}/src/com/blockstream/libwally/Wally.java
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src
)
else(${CMAKE_VERSION} VERSION_LESS "3.17.0")
add_custom_command(
    TARGET ${WALLY_SWIG_JAVA_NAME}
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E rm -f ${JAVA_INTERFACE_FILE}
    COMMAND ${CMAKE_COMMAND} -E copy  ${CMAKE_CURRENT_BINARY_DIR}/Wally.java ${SWIG_JAVA_SOURCE_DIR}/wallycoreJNI.java
    COMMAND ${CMAKE_COMMAND} -E copy  ${CMAKE_CURRENT_BINARY_DIR}/wallycoreConstants.java ${SWIG_JAVA_SOURCE_DIR}/wallycoreConstants.java
#    COMMAND sed -i 's/ = (char \*) (\*jenv)\->Get/ = (unsigned char \*) (\*jenv)\->Get/g' ${OUT_JAVA_FILE}
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tools/swigjavapost.sh sed ${ELEMENTS_COMP_OPT}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${SWIG_JAVA_OUTPUT_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${SWIG_JAVA_SOURCE_DIR}/src ${SWIG_JAVA_OUTPUT_DIR}/src
    COMMAND ${CMAKE_COMMAND} -E rm -f ${SWIG_JAVA_SOURCE_DIR}/src/com/blockstream/libwally/Wally.java
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src
)
endif(${CMAKE_VERSION} VERSION_LESS "3.17.0")

set(SWIG_JAVA_JAR_NAME wallycore_swig_java_jar)

project (${SWIG_JAVA_JAR_NAME} NONE)
set(CMAKE_JAVA_COMPILE_FLAGS "-source" "${JAVAC_TARGET}" "-target" "${JAVAC_TARGET}")
set(SWIG_JAVA_WALLY_FILE  ${SWIG_JAVA_PACKAGE_DIR}/Wally.java)
set(OUT_JAR_FILE    ${SWIG_JAVA_OUTPUT_DIR}/wallycore.jar)
add_jar(${SWIG_JAVA_JAR_NAME}
    SOURCES ${SWIG_JAVA_WALLY_FILE}
    OUTPUT_NAME wallycore
    OUTPUT_DIR ${SWIG_JAVA_OUTPUT_DIR}
)
add_dependencies(${SWIG_JAVA_JAR_NAME} ${WALLY_SWIG_JAVA_NAME})

if(ENABLE_SHARED)
add_custom_command(
    TARGET ${SWIG_JAVA_JAR_NAME}
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy  ${OUT_JAR_FILE} ${WALLY_OBJ_BINARY_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy  ${WALLY_OBJ_BINARY_DIR}/libwallycore.so ${SWIG_JAVA_OUTPUT_DIR}
)
else()
add_custom_command(
    TARGET ${SWIG_JAVA_JAR_NAME}
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy  ${OUT_JAR_FILE} ${WALLY_OBJ_BINARY_DIR}
)
endif()

endif()		# ENABLE_SWIG_JAVA


####################
# test
####################
if(ENABLE_TESTS)
enable_testing()
project(wally_test C)
include(CTest)
# add_subdirectory(src/ctest)
if(NOT WIN32)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY  ${WALLY_OBJ_BINARY_DIR})
endif()

####################
# test for C
####################
set(TEST_WALY_LIB  ${WALLY_PROJECT_NAME})
# set(TEST_WALY_LIB  ${WALLYCORE_NAME})

if((ENABLE_SWIG_JAVA OR ENABLE_JS_WRAPPER) AND (NOT GENERATE_WALLY_LIB))
message(STATUS "skip c test.")
else()
set(TEST_BECH32_NAME ctest_bech32)
add_executable(${TEST_BECH32_NAME} src/ctest/test_bech32.c)
target_compile_options(${TEST_BECH32_NAME}
  PRIVATE
    $<IF:$<C_COMPILER_ID:MSVC>,
      /source-charset:utf-8 /wd4251,
      -Wall -Wextra -Wno-unused-function
      ${PROFILE_ARCS_OPT} ${TEST_COVERAGE_OPT}
    >
)
target_compile_definitions(${TEST_BECH32_NAME}
  PRIVATE
    ${ELEMENTS_COMP_OPT}
)
target_include_directories(${TEST_BECH32_NAME}
  PRIVATE
    ${CONFIG_HEADER_DIRECTORY}
    .
    src
    src/ccan
    src/secp256k1
    src/secp256k1/src
    ${SECP256K_OUTPUT_PATH}
)
target_link_directories(${TEST_BECH32_NAME}  PRIVATE ./ )
target_link_libraries(${TEST_BECH32_NAME}
  PRIVATE $<$<BOOL:$<C_COMPILER_ID:MSVC>>:winmm.lib>
  PRIVATE $<$<BOOL:$<C_COMPILER_ID:MSVC>>:ws2_32.lib>
  PRIVATE $<IF:$<OR:$<PLATFORM_ID:Darwin>,$<PLATFORM_ID:Windows>>,,rt>
  PRIVATE $<$<BOOL:$<C_COMPILER_ID:GCC>>:-static-libgcc>
  PRIVATE $<$<NOT:$<C_COMPILER_ID:MSVC>>:pthread>
  PRIVATE
    ${TEST_WALY_LIB}
)
add_test(
  NAME ${TEST_BECH32_NAME}
  COMMAND ${TEST_BECH32_NAME}
  WORKING_DIRECTORY ${WALLY_OBJ_BINARY_DIR}
)

if(Clang) # use pthread and LLVM Clang
set(TEST_CLEAR_NAME ctest_clear)
add_executable(${TEST_CLEAR_NAME} src/ctest/test_clear.c)
target_compile_options(${TEST_CLEAR_NAME}
  PRIVATE
    $<IF:$<C_COMPILER_ID:MSVC>,
      /source-charset:utf-8 /wd4251,
      -Wall -Wextra -Wno-unused-function
      ${PROFILE_ARCS_OPT} ${TEST_COVERAGE_OPT}
    >
)
target_compile_definitions(${TEST_CLEAR_NAME}
  PRIVATE
    ${ELEMENTS_COMP_OPT}
)
target_include_directories(${TEST_CLEAR_NAME}
  PRIVATE
    ${CONFIG_HEADER_DIRECTORY}
    .
    src
    src/ccan
    src/secp256k1
    src/secp256k1/src
    ${SECP256K_OUTPUT_PATH}
)
target_link_directories(${TEST_CLEAR_NAME}  PRIVATE ./ )
target_link_libraries(${TEST_CLEAR_NAME}
  PRIVATE $<$<BOOL:$<C_COMPILER_ID:MSVC>>:winmm.lib>
  PRIVATE $<$<BOOL:$<C_COMPILER_ID:MSVC>>:ws2_32.lib>
  PRIVATE $<IF:$<OR:$<PLATFORM_ID:Darwin>,$<PLATFORM_ID:Windows>>,,rt>
  PRIVATE $<$<BOOL:$<C_COMPILER_ID:GCC>>:-static-libgcc>
  PRIVATE $<$<NOT:$<C_COMPILER_ID:MSVC>>:pthread>
  PRIVATE
    ${TEST_WALY_LIB}
)
add_test(
  NAME ${TEST_CLEAR_NAME}
  COMMAND $<TARGET_FILE:${TEST_CLEAR_NAME}>
  WORKING_DIRECTORY ${WALLY_OBJ_BINARY_DIR}
)
endif() # Clang

set(TEST_TX_NAME ctest_tx)
add_executable(${TEST_TX_NAME} src/ctest/test_tx.c)
target_compile_options(${TEST_TX_NAME}
  PRIVATE
    $<IF:$<C_COMPILER_ID:MSVC>,
      /source-charset:utf-8 /wd4251,
      -Wall -Wextra -Wno-unused-function
      ${PROFILE_ARCS_OPT} ${TEST_COVERAGE_OPT}
    >
)
target_compile_definitions(${TEST_TX_NAME}
  PRIVATE
    ${ELEMENTS_COMP_OPT}
)
target_include_directories(${TEST_TX_NAME}
  PRIVATE
    ${CONFIG_HEADER_DIRECTORY}
    .
    src
    src/ccan
    src/secp256k1
    src/secp256k1/src
    ${SECP256K_OUTPUT_PATH}
)
target_link_directories(${TEST_TX_NAME}  PRIVATE ./ )
target_link_libraries(${TEST_TX_NAME}
  PRIVATE $<$<BOOL:$<C_COMPILER_ID:MSVC>>:winmm.lib>
  PRIVATE $<$<BOOL:$<C_COMPILER_ID:MSVC>>:ws2_32.lib>
  PRIVATE $<IF:$<OR:$<PLATFORM_ID:Darwin>,$<PLATFORM_ID:Windows>>,,rt>
  PRIVATE $<$<BOOL:$<C_COMPILER_ID:GCC>>:-static-libgcc>
  PRIVATE $<$<NOT:$<C_COMPILER_ID:MSVC>>:pthread>
  PRIVATE
    ${TEST_WALY_LIB}
)
add_test(
  NAME ${TEST_TX_NAME}
  COMMAND $<TARGET_FILE:${TEST_TX_NAME}>
  WORKING_DIRECTORY ${WALLY_OBJ_BINARY_DIR}
)

set(TEST_DESCRIPTOR_NAME ctest_descriptor)
add_executable(${TEST_DESCRIPTOR_NAME} src/ctest/test_descriptor.c)
target_compile_options(${TEST_DESCRIPTOR_NAME}
  PRIVATE
    $<IF:$<C_COMPILER_ID:MSVC>,
      /source-charset:utf-8 /wd4251,
      -Wall -Wextra -Wno-unused-function
      ${PROFILE_ARCS_OPT} ${TEST_COVERAGE_OPT}
    >
)
target_compile_definitions(${TEST_DESCRIPTOR_NAME}
  PRIVATE
    ${ELEMENTS_COMP_OPT}
)
target_include_directories(${TEST_DESCRIPTOR_NAME}
  PRIVATE
    ${CONFIG_HEADER_DIRECTORY}
    .
    src
    src/ccan
    src/secp256k1
    src/secp256k1/src
    ${SECP256K_OUTPUT_PATH}
)
target_link_directories(${TEST_DESCRIPTOR_NAME}  PRIVATE ./ )
target_link_libraries(${TEST_DESCRIPTOR_NAME}
  PRIVATE $<$<BOOL:$<C_COMPILER_ID:MSVC>>:winmm.lib>
  PRIVATE $<$<BOOL:$<C_COMPILER_ID:MSVC>>:ws2_32.lib>
  PRIVATE $<IF:$<OR:$<PLATFORM_ID:Darwin>,$<PLATFORM_ID:Windows>>,,rt>
  PRIVATE $<$<BOOL:$<C_COMPILER_ID:GCC>>:-static-libgcc>
  PRIVATE $<$<NOT:$<C_COMPILER_ID:MSVC>>:pthread>
  PRIVATE
    ${TEST_WALY_LIB}
)
add_test(
  NAME ${TEST_DESCRIPTOR_NAME}
  COMMAND $<TARGET_FILE:${TEST_DESCRIPTOR_NAME}>
  WORKING_DIRECTORY ${WALLY_OBJ_BINARY_DIR}
)

####################
# test for C(secp256k1)
####################
if(ENABLE_SECP256K1_TEST AND ${ENABLE_SECP256K1_TEST})
set(TEST_SECP256K1_NAME ctest_secp256k1)
set(TEST_SECP256K1_FILES
    src/secp256k1/src/tests.c
    ${CONFIG_HEADER_DIRECTORY}/libsecp256k1-config.h
    src/secp256k1/include/secp256k1.h
    src/secp256k1/include/secp256k1_recovery.h
    ${ECMULT_STATIC_CONTEXT_H}
)
add_executable(${TEST_SECP256K1_NAME} ${TEST_SECP256K1_FILES})
target_compile_options(${TEST_SECP256K1_NAME}
  PRIVATE
    $<IF:$<C_COMPILER_ID:MSVC>,
      /source-charset:utf-8 /wd4251,
      -Wall -Wextra -Wno-unused-function
      ${PROFILE_ARCS_OPT} ${TEST_COVERAGE_OPT}
    >
)
target_compile_definitions(${TEST_SECP256K1_NAME}
  PRIVATE
    SECP256K1_BUILD
    HAVE_CONFIG_H
)
target_include_directories(${TEST_SECP256K1_NAME}
  PRIVATE
    ${CONFIG_HEADER_DIRECTORY}
    .
    src/secp256k1
    src/secp256k1/include
    src/secp256k1/src
    ${SECP256K_OUTPUT_PATH}
)
target_link_directories(${TEST_SECP256K1_NAME}  PRIVATE ./ )
target_link_libraries(${TEST_SECP256K1_NAME}
  PRIVATE $<$<BOOL:$<C_COMPILER_ID:MSVC>>:winmm.lib>
  PRIVATE $<$<BOOL:$<C_COMPILER_ID:MSVC>>:ws2_32.lib>
  PRIVATE $<IF:$<OR:$<PLATFORM_ID:Darwin>,$<PLATFORM_ID:Windows>>,,rt>
  PRIVATE $<$<BOOL:$<C_COMPILER_ID:GCC>>:-static-libgcc>
  PRIVATE $<$<NOT:$<C_COMPILER_ID:MSVC>>:pthread>
)
add_test(
  NAME ${TEST_SECP256K1_NAME}
  COMMAND $<TARGET_FILE:${TEST_SECP256K1_NAME}>
  WORKING_DIRECTORY ${WALLY_OBJ_BINARY_DIR}
)
endif(ENABLE_SECP256K1_TEST AND ${ENABLE_SECP256K1_TEST})

####################
# test for C(Elements)
####################
if(ENABLE_ELEMENTS)
set(TEST_ELEMENTS_TX_NAME ctest_elements_tx)
add_executable(${TEST_ELEMENTS_TX_NAME} src/ctest/test_elements_tx.c)
target_compile_options(${TEST_ELEMENTS_TX_NAME}
  PRIVATE
    $<IF:$<C_COMPILER_ID:MSVC>,
      /source-charset:utf-8 /wd4251,
      -Wall -Wextra -Wno-unused-function
      ${PROFILE_ARCS_OPT} ${TEST_COVERAGE_OPT}
    >
)
target_compile_definitions(${TEST_ELEMENTS_TX_NAME}
  PRIVATE
    ${ELEMENTS_COMP_OPT}
)
target_include_directories(${TEST_ELEMENTS_TX_NAME}
  PRIVATE
    ${CONFIG_HEADER_DIRECTORY}
    .
    src
    src/ccan
    src/secp256k1
    src/secp256k1/src
    ${SECP256K_OUTPUT_PATH}
)
target_link_directories(${TEST_ELEMENTS_TX_NAME}  PRIVATE ./ )
target_link_libraries(${TEST_ELEMENTS_TX_NAME}
  PRIVATE $<$<BOOL:$<C_COMPILER_ID:MSVC>>:winmm.lib>
  PRIVATE $<$<BOOL:$<C_COMPILER_ID:MSVC>>:ws2_32.lib>
  PRIVATE $<IF:$<OR:$<PLATFORM_ID:Darwin>,$<PLATFORM_ID:Windows>>,,rt>
  PRIVATE $<$<BOOL:$<C_COMPILER_ID:GCC>>:-static-libgcc>
  PRIVATE $<$<NOT:$<C_COMPILER_ID:MSVC>>:pthread>
  PRIVATE
    ${TEST_WALY_LIB}
)
add_test(
  NAME ${TEST_ELEMENTS_TX_NAME}
  COMMAND $<TARGET_FILE:${TEST_ELEMENTS_TX_NAME}>
  WORKING_DIRECTORY ${WALLY_OBJ_BINARY_DIR}
)

set(TEST_BLECH32_NAME ctest_blech32)
add_executable(${TEST_BLECH32_NAME} src/ctest/test_blech32.c)
target_compile_options(${TEST_BLECH32_NAME}
  PRIVATE
    $<IF:$<C_COMPILER_ID:MSVC>,
      /source-charset:utf-8 /wd4251,
      -Wall -Wextra -Wno-unused-function
      ${PROFILE_ARCS_OPT} ${TEST_COVERAGE_OPT}
    >
)
target_compile_definitions(${TEST_BLECH32_NAME}
  PRIVATE
    ${ELEMENTS_COMP_OPT}
)
target_include_directories(${TEST_BLECH32_NAME}
  PRIVATE
    ${CONFIG_HEADER_DIRECTORY}
    .
    src
    src/ccan
    src/secp256k1
    src/secp256k1/src
    ${SECP256K_OUTPUT_PATH}
)
target_link_directories(${TEST_BLECH32_NAME}  PRIVATE ./ )
target_link_libraries(${TEST_BLECH32_NAME}
  PRIVATE $<$<BOOL:$<C_COMPILER_ID:MSVC>>:winmm.lib>
  PRIVATE $<$<BOOL:$<C_COMPILER_ID:MSVC>>:ws2_32.lib>
  PRIVATE $<IF:$<OR:$<PLATFORM_ID:Darwin>,$<PLATFORM_ID:Windows>>,,rt>
  PRIVATE $<$<BOOL:$<C_COMPILER_ID:GCC>>:-static-libgcc>
  PRIVATE $<$<NOT:$<C_COMPILER_ID:MSVC>>:pthread>
  PRIVATE
    ${TEST_WALY_LIB}
)
add_test(
  NAME ${TEST_BLECH32_NAME}
  COMMAND $<TARGET_FILE:${TEST_BLECH32_NAME}>
  WORKING_DIRECTORY ${WALLY_OBJ_BINARY_DIR}
)
endif()
endif((ENABLE_SWIG_JAVA OR ENABLE_JS_WRAPPER) AND (NOT GENERATE_WALLY_LIB))

####################
# test for Python
####################
if(ENABLE_SWIG_PYTHON)
set(SWIG_PY_TEST_DIR ${SWIG_PY_OUTPUT_DIR}/contrib)

set(PY_TEST_DIR ${SWIG_PY_OUTPUT_DIR}/contrib)
find_package(Python3 COMPONENTS Interpreter)
find_package(PythonInterp REQUIRED)
if(Python3_Interpreter_FOUND)
set(PYTHON_BIN  ${Python3_EXECUTABLE})
message(STATUS "python is 3(${Python3_VERSION})")
else()
set(PYTHON_BIN  ${PYTHON_EXECUTABLE})
message(STATUS "python version is ${PYTHON_VERSION_STRING}")
endif()

# copy testfile
add_test(NAME py_test_init1 COMMAND ${CMAKE_COMMAND} -E copy_directory ${SWIG_PY_SOURCE_DIR}/contrib ${SWIG_PY_OUTPUT_DIR}/contrib )
add_test(NAME py_test_init2 COMMAND ${CMAKE_COMMAND} -E copy_directory ${SWIG_PY_OUTPUT_DIR}/wallycore ${SWIG_PY_TEST_DIR}/wallycore )
if(MSVC)
add_test(NAME py_test_init3 COMMAND ${CMAKE_COMMAND} -E copy_directory ${SWIG_PY_OUTPUT_DIR}/wallycore ${SWIG_PY_TEST_DIR} )
endif()

if(ENABLE_ELEMENTS)
set(SWIG_PY_EXAMPLE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src/pyexample)
add_test(NAME py_test_init4 COMMAND ${CMAKE_COMMAND} -E copy_directory ${SWIG_PY_EXAMPLE_DIR}/liquid ${SWIG_PY_OUTPUT_DIR}/contrib )
endif()

add_test(NAME py_test_bip32           COMMAND ${PYTHON_BIN} ${SWIG_PY_TEST_DIR}/bip32.py )
add_test(NAME py_test_mnemonic        COMMAND ${PYTHON_BIN} ${SWIG_PY_TEST_DIR}/mnemonic.py )
add_test(NAME py_test_reconcile_sigs  COMMAND ${PYTHON_BIN} ${SWIG_PY_TEST_DIR}/reconcile_sigs.py )
add_test(NAME py_test_signmessage     COMMAND ${PYTHON_BIN} ${SWIG_PY_TEST_DIR}/signmessage.py )
add_test(NAME py_test_tx              COMMAND ${PYTHON_BIN} ${SWIG_PY_TEST_DIR}/tx.py )
add_test(NAME py_test_address         COMMAND ${PYTHON_BIN} ${SWIG_PY_TEST_DIR}/address.py )
add_test(NAME py_test_sha             COMMAND ${PYTHON_BIN} ${SWIG_PY_TEST_DIR}/sha.py )

if(ENABLE_ELEMENTS)
add_test(NAME py_test_elements_tx     COMMAND ${PYTHON_BIN} ${SWIG_PY_TEST_DIR}/elements_tx.py )

add_test(NAME py_test_liquid          COMMAND ${PYTHON_BIN} ${SWIG_PY_TEST_DIR}/receive-send.py )
endif() # ENABLE_ELEMENTS

endif()


####################
# test with Python
####################
## error occurred on mingw
if(WIN32)
if(MSVC)
set(WIN_MINGW  FALSE)
else()
set(WIN_MINGW  TRUE)
endif()
else()
set(WIN_MINGW  FALSE)
endif()

## error occurred on windows
if(${ENABLE_SHARED} AND ${INSTALL_WALLYCORE} AND (NOT ${WIN_MINGW}))
if(WIN32)
set(PY_TEST_IGNORE  TRUE)
else()
set(PY_TEST_IGNORE  FALSE)
endif()
set(PY_TEST_DIR ${WALLY_ROOT_BINARY_DIR}/wally_test/src/.libs)
set(PY_TEST_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src/test)

find_package(Python3 COMPONENTS Interpreter)
find_package(PythonInterp REQUIRED)
if(Python3_Interpreter_FOUND)
set(PYTHON_BIN  ${Python3_EXECUTABLE})
message(STATUS "python is 3(${Python3_VERSION})")
else()
set(PYTHON_BIN  ${PYTHON_EXECUTABLE})
message(STATUS "python version is ${PYTHON_VERSION_STRING}")
endif()

message(STATUS "[test] copy libwallycore${CMAKE_SHARED_LIBRARY_SUFFIX}")
# copy testfile
add_test(NAME test_init1 COMMAND ${CMAKE_COMMAND} -E make_directory ${PY_TEST_DIR} )
add_test(NAME test_init2 COMMAND ${CMAKE_COMMAND} -E copy_directory ${PY_TEST_SOURCE_DIR} ${PY_TEST_DIR}/test )
add_test(NAME test_init3 COMMAND ${CMAKE_COMMAND} -E copy ${WALLY_OBJ_BINARY_DIR}/libwallycore${CMAKE_SHARED_LIBRARY_SUFFIX} ${PY_TEST_DIR} )
add_test(NAME test_init4 COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/src/data ${WALLY_ROOT_BINARY_DIR}/wally_test/src/data )


add_test(NAME test_address      COMMAND ${PYTHON_BIN} test/test_address.py
                                WORKING_DIRECTORY ${PY_TEST_DIR})
add_test(NAME test_aes          COMMAND ${PYTHON_BIN} test/test_aes.py
                                WORKING_DIRECTORY ${PY_TEST_DIR})
add_test(NAME test_base58       COMMAND ${PYTHON_BIN} test/test_base58.py
                                WORKING_DIRECTORY ${PY_TEST_DIR})
add_test(NAME test_bech32       COMMAND ${PYTHON_BIN} test/test_bech32.py
                                WORKING_DIRECTORY ${PY_TEST_DIR})
add_test(NAME test_bip32        COMMAND ${PYTHON_BIN} test/test_bip32.py
                                WORKING_DIRECTORY ${PY_TEST_DIR})
add_test(NAME test_bip38        COMMAND ${PYTHON_BIN} test/test_bip38.py
                                WORKING_DIRECTORY ${PY_TEST_DIR})
add_test(NAME test_bip39        COMMAND ${PYTHON_BIN} test/test_bip39.py
                                WORKING_DIRECTORY ${PY_TEST_DIR})
add_test(NAME test_ecdh         COMMAND ${PYTHON_BIN} test/test_ecdh.py
                                WORKING_DIRECTORY ${PY_TEST_DIR})
add_test(NAME test_hash         COMMAND ${PYTHON_BIN} test/test_hash.py
                                WORKING_DIRECTORY ${PY_TEST_DIR})
add_test(NAME test_hex          COMMAND ${PYTHON_BIN} test/test_hex.py
                                WORKING_DIRECTORY ${PY_TEST_DIR})
add_test(NAME test_hmac         COMMAND ${PYTHON_BIN} test/test_hmac.py
                                WORKING_DIRECTORY ${PY_TEST_DIR})
add_test(NAME test_mnemonic     COMMAND ${PYTHON_BIN} test/test_mnemonic.py
                                WORKING_DIRECTORY ${PY_TEST_DIR})
add_test(NAME test_pbkdf2       COMMAND ${PYTHON_BIN} test/test_pbkdf2.py
                                WORKING_DIRECTORY ${PY_TEST_DIR})
add_test(NAME test_script       COMMAND ${PYTHON_BIN} test/test_script.py
                                WORKING_DIRECTORY ${PY_TEST_DIR})
add_test(NAME test_scrypt       COMMAND ${PYTHON_BIN} test/test_scrypt.py
                                WORKING_DIRECTORY ${PY_TEST_DIR})
add_test(NAME test_wif          COMMAND ${PYTHON_BIN} test/test_wif.py
                                WORKING_DIRECTORY ${PY_TEST_DIR})
add_test(NAME test_wordlist     COMMAND ${PYTHON_BIN} test/test_wordlist.py
                                WORKING_DIRECTORY ${PY_TEST_DIR})
add_test(NAME test_descriptor   COMMAND ${PYTHON_BIN} test/test_descriptor.py
                                WORKING_DIRECTORY ${PY_TEST_DIR})
if(NOT PY_TEST_IGNORE)
add_test(NAME test_psbt         COMMAND ${PYTHON_BIN} test/test_psbt.py
                                WORKING_DIRECTORY ${PY_TEST_DIR})
add_test(NAME test_transaction  COMMAND ${PYTHON_BIN} test/test_transaction.py
                                WORKING_DIRECTORY ${PY_TEST_DIR})
endif(NOT PY_TEST_IGNORE)

if(ENABLE_ELEMENTS)
add_test(NAME test_elements           COMMAND ${PYTHON_BIN} test/test_elements.py
                                      WORKING_DIRECTORY ${PY_TEST_DIR})
add_test(NAME test_confidential_addr  COMMAND ${PYTHON_BIN} test/test_confidential_addr.py
                                      WORKING_DIRECTORY ${PY_TEST_DIR})
if(NOT PY_TEST_IGNORE)
add_test(NAME test_pegin              COMMAND ${PYTHON_BIN} test/test_pegin.py
                                      WORKING_DIRECTORY ${PY_TEST_DIR})
add_test(NAME test_pegout             COMMAND ${PYTHON_BIN} test/test_pegout.py
                                      WORKING_DIRECTORY ${PY_TEST_DIR})
endif(NOT PY_TEST_IGNORE)
endif() # ENABLE_ELEMENTS
endif() # ${ENABLE_SHARED} AND ${INSTALL_WALLYCORE}

####################
# test for Java
####################
if(${ENABLE_SWIG_JAVA} AND ${ENABLE_SHARED})
project (swig_java_test NONE)
set(SWIG_JAVA_TEST_PACKAGE_DIR ${SWIG_JAVA_OUTPUT_DIR}/src/com/blockstream/test)
set(CMAKE_JAVA_COMPILE_FLAGS "-source" "${JAVAC_TARGET}" "-target" "${JAVAC_TARGET}")

set(TEST_JAVA_BIP32 java_test_bip32)
add_jar(${TEST_JAVA_BIP32}
  SOURCES
    ${SWIG_JAVA_TEST_PACKAGE_DIR}/test_bip32.java
    ${SWIG_JAVA_WALLY_FILE}
  ENTRY_POINT com/blockstream/test/test_bip32
  OUTPUT_NAME ${TEST_JAVA_BIP32}
  OUTPUT_DIR ${SWIG_JAVA_OUTPUT_DIR}
)
add_dependencies(${TEST_JAVA_BIP32} ${SWIG_JAVA_JAR_NAME})
add_test(
  NAME ${TEST_JAVA_BIP32}
  COMMAND
    ${CMAKE_COMMAND} -E env LD_LIBRARY_PATH=.
    java -jar ${TEST_JAVA_BIP32}.jar
  WORKING_DIRECTORY ${SWIG_JAVA_OUTPUT_DIR}
)

set(TEST_JAVA_NEMONIC java_test_nemonic)
add_jar(${TEST_JAVA_NEMONIC}
  SOURCES
    ${SWIG_JAVA_TEST_PACKAGE_DIR}/test_mnemonic.java
    ${SWIG_JAVA_WALLY_FILE}
  ENTRY_POINT com/blockstream/test/test_mnemonic
  OUTPUT_NAME ${TEST_JAVA_NEMONIC}
  OUTPUT_DIR ${SWIG_JAVA_OUTPUT_DIR}
)
add_dependencies(${TEST_JAVA_NEMONIC} ${SWIG_JAVA_JAR_NAME})
add_test(
  NAME ${TEST_JAVA_NEMONIC}
  COMMAND
    ${CMAKE_COMMAND} -E env LD_LIBRARY_PATH=.
    java -jar ${TEST_JAVA_NEMONIC}.jar
  WORKING_DIRECTORY ${SWIG_JAVA_OUTPUT_DIR}
)

set(TEST_JAVA_TX java_test_tx)
add_jar(${TEST_JAVA_TX}
  SOURCES
    ${SWIG_JAVA_TEST_PACKAGE_DIR}/test_tx.java
    ${SWIG_JAVA_WALLY_FILE}
  ENTRY_POINT com/blockstream/test/test_tx
  OUTPUT_NAME ${TEST_JAVA_TX}
  OUTPUT_DIR ${SWIG_JAVA_OUTPUT_DIR}
)
add_dependencies(${TEST_JAVA_TX} ${SWIG_JAVA_JAR_NAME})
add_test(
  NAME ${TEST_JAVA_TX}
  COMMAND
    ${CMAKE_COMMAND} -E env LD_LIBRARY_PATH=.
    java -jar ${TEST_JAVA_TX}.jar
  WORKING_DIRECTORY ${SWIG_JAVA_OUTPUT_DIR}
)

set(TEST_JAVA_SCRIPTS java_test_scripts)
add_jar(${TEST_JAVA_SCRIPTS}
  SOURCES
    ${SWIG_JAVA_TEST_PACKAGE_DIR}/test_scripts.java
    ${SWIG_JAVA_WALLY_FILE}
  ENTRY_POINT com/blockstream/test/test_scripts
  OUTPUT_NAME ${TEST_JAVA_SCRIPTS}
  OUTPUT_DIR ${SWIG_JAVA_OUTPUT_DIR}
)
add_dependencies(${TEST_JAVA_SCRIPTS} ${SWIG_JAVA_JAR_NAME})
add_test(
  NAME ${TEST_JAVA_SCRIPTS}
  COMMAND
    ${CMAKE_COMMAND} -E env LD_LIBRARY_PATH=.
    java -jar ${TEST_JAVA_SCRIPTS}.jar
  WORKING_DIRECTORY ${SWIG_JAVA_OUTPUT_DIR}
)

if(ENABLE_ELEMENTS)
set(TEST_JAVA_ASSETS java_test_assets)
add_jar(${TEST_JAVA_ASSETS}
  SOURCES
    ${SWIG_JAVA_TEST_PACKAGE_DIR}/test_assets.java
    ${SWIG_JAVA_WALLY_FILE}
  ENTRY_POINT com/blockstream/test/test_assets
  OUTPUT_NAME ${TEST_JAVA_ASSETS}
  OUTPUT_DIR ${SWIG_JAVA_OUTPUT_DIR}
)
add_dependencies(${TEST_JAVA_ASSETS} ${SWIG_JAVA_JAR_NAME})
add_test(
  NAME ${TEST_JAVA_ASSETS}
  COMMAND
    ${CMAKE_COMMAND} -E env LD_LIBRARY_PATH=.
    java -jar ${TEST_JAVA_ASSETS}.jar
  WORKING_DIRECTORY ${SWIG_JAVA_OUTPUT_DIR}
)

set(TEST_JAVA_PEGS java_test_pegs)
add_jar(${TEST_JAVA_PEGS}
  SOURCES
    ${SWIG_JAVA_TEST_PACKAGE_DIR}/test_pegs.java
    ${SWIG_JAVA_WALLY_FILE}
  ENTRY_POINT com/blockstream/test/test_pegs
  OUTPUT_NAME ${TEST_JAVA_PEGS}
  OUTPUT_DIR ${SWIG_JAVA_OUTPUT_DIR}
)
add_dependencies(${TEST_JAVA_PEGS} ${SWIG_JAVA_JAR_NAME})
add_test(
  NAME ${TEST_JAVA_PEGS}
  COMMAND
    ${CMAKE_COMMAND} -E env LD_LIBRARY_PATH=.
    java -jar ${TEST_JAVA_PEGS}.jar
  WORKING_DIRECTORY ${SWIG_JAVA_OUTPUT_DIR}
)
endif() # ENABLE_ELEMENTS

endif()

####################
# test for node.js
####################
# Currently, wally.js only supports release builds.
if(ENABLE_JS_WRAPPER)
# 'tape' is notfound on Windows, So it's call to 'node'.
# (testfile is direct require to 'tape'.)
set(NODE_TEST_BIN  node)

# set(NODE_BIN_TAPE  ${CMAKE_CURRENT_SOURCE_DIR}/node_modules/.bin/tape)
# if(WIN32)
# set(CMAKE_MSVCIDE_RUN_PATH ${NODE_BIN_TAPE})
# endif()

# copy testfile on pre-test (for load on wallycore.node)
add_test(NAME js_test_init1 COMMAND ${CMAKE_COMMAND} -E copy ${WALLY_OBJ_BINARY_DIR}/wallycore.node ${NODE_TEST_RELEASE_DIR} )
add_test(NAME js_test_init2 COMMAND ${CMAKE_COMMAND} -E copy_directory ${NODE_TEST_SRC_DIR} ${NODE_TEST_FILE_DIR} )

add_test(NAME js_test_aes      COMMAND ${NODE_TEST_BIN} ${NODE_TEST_FILE_DIR}/test_aes.js )
add_test(NAME js_test_base58   COMMAND ${NODE_TEST_BIN} ${NODE_TEST_FILE_DIR}/test_base58.js )
add_test(NAME js_test_bip32    COMMAND ${NODE_TEST_BIN} ${NODE_TEST_FILE_DIR}/test_bip32.js )
add_test(NAME js_test_bip38    COMMAND ${NODE_TEST_BIN} ${NODE_TEST_FILE_DIR}/test_bip38.js )
add_test(NAME js_test_bip39    COMMAND ${NODE_TEST_BIN} ${NODE_TEST_FILE_DIR}/test_bip39.js )
add_test(NAME js_test_hash     COMMAND ${NODE_TEST_BIN} ${NODE_TEST_FILE_DIR}/test_hash.js )
add_test(NAME js_test_scrypt   COMMAND ${NODE_TEST_BIN} ${NODE_TEST_FILE_DIR}/test_scrypt.js )
add_test(NAME js_test_script   COMMAND ${NODE_TEST_BIN} ${NODE_TEST_FILE_DIR}/test_script.js )
if(ENABLE_ELEMENTS)
add_test(NAME js_test_assets   COMMAND ${NODE_TEST_BIN} ${NODE_TEST_FILE_DIR}/test_assets.js )
add_test(NAME js_test_unblind  COMMAND ${NODE_TEST_BIN} ${NODE_TEST_FILE_DIR}/test_unblind.js )
add_test(NAME js_test_confidential_address
    COMMAND ${NODE_TEST_BIN} ${NODE_TEST_FILE_DIR}/test_confidential_address.js )
endif() # ENABLE_ELEMENTS
endif() # ENABLE_JS_WRAPPER

endif() # ENABLE_TESTS


####################
# coverage
####################
if(ENABLE_DEBUG AND ENABLE_COVERAGE)
if(${WALLY_PROJECT_NAME} STREQUAL "wally")
set(WALLY_COVERAGE_DIR  ${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/wally.dir)
else()
set(WALLY_COVERAGE_DIR  ${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/wallycore.dir)
endif()

add_custom_target(
  lcov_libwally_init ${CMAKE_COMMAND} -E make_directory ${WALLY_ROOT_BINARY_DIR}/lcov_wally_output
  WORKING_DIRECTORY ${WALLY_COVERAGE_DIR}
)

add_custom_target(
  lcov_libwally_collect_src
  lcov --directory=src/ --base-directory src/ --output-file wally.info --capture --ignore-errors=gcov
  DEPENDS lcov_libwally_init
  WORKING_DIRECTORY ${WALLY_COVERAGE_DIR}
)

add_custom_target(
  coverage_libwally  genhtml -o ${WALLY_ROOT_BINARY_DIR}/lcov_wally_output wally.info
  DEPENDS lcov_libwally_init lcov_libwally_collect_src
  WORKING_DIRECTORY ${WALLY_COVERAGE_DIR}
)
endif()


####################
# install & export
####################
set(prefix            ${CMAKE_INSTALL_PREFIX})
set(exec_prefix       ${prefix})
set(libdir            ${exec_prefix}/lib)
set(includedir        ${prefix}/include)
include(GNUInstallDirs)
set(CMAKE_INCLUDE_CURRENT_DIR_IN_INTERFACE ON) 

if(INSTALL_WALLYCORE)
configure_file(src/wallycore.pc.in  wallycore.pc  @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/wallycore.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

install(TARGETS       ${WALLY_PROJECT_NAME}
        EXPORT        wallycore-export
        ARCHIVE       DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY       DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME       DESTINATION ${CMAKE_INSTALL_LIBDIR}
        OBJECTS       DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(EXPORT ${WALLY_PROJECT_NAME}-export
        FILE ${WALLY_PROJECT_NAME}-config.cmake
        DESTINATION "cmake/"
        EXPORT_LINK_INTERFACE_LIBRARIES)
if(MSVC)
install(DIRECTORY "${WALLY_OBJ_BINARY_DIR}/"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        FILES_MATCHING PATTERN "wallycore.exp")
endif()
endif()

if(GENERATE_WALLY_LIB)
configure_file(cmake/wally.pc.in  wally.pc  @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/wally.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
install(TARGETS       wally
        EXPORT        wally-export
        ARCHIVE       DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY       DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME       DESTINATION ${CMAKE_INSTALL_LIBDIR}
        OBJECTS       DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(EXPORT wally-export
        FILE wally-config.cmake
        DESTINATION "cmake/"
        EXPORT_LINK_INTERFACE_LIBRARIES)
if(MSVC)
install(DIRECTORY "${WALLY_OBJ_BINARY_DIR}/"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        FILES_MATCHING PATTERN "wally.exp")
endif()
endif()

if(INSTALL_WALLYCORE OR GENERATE_WALLY_LIB)
install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
        FILES_MATCHING REGEX "/[^/]*\\.(h|hpp)$")
install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1/include/"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
        FILES_MATCHING PATTERN "*.h")
endif()
