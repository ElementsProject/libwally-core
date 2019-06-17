cmake_minimum_required(VERSION 3.13)

# wally project
project(wally C)
cmake_policy(SET CMP0076 NEW)
set(CMAKE_VERBOSE_MAKEFILE TRUE)

# options
if(CMAKE_JS_INC)
option(ENABLE_SHARED "enable shared library (ON or OFF. default:ON)" ON)
else()
option(ENABLE_SHARED "enable shared library (ON or OFF. default:OFF)" OFF)
endif()
option(ENABLE_DEBUG "enable debugging (ON or OFF. default:OFF)" OFF)
option(ENABLE_COVERAGE "enable code coverage (ON or OFF. default:OFF)" OFF)
option(ENABLE_TESTS "enable code tests (ON or OFF. default:ON)" ON)
option(ENABLE_ELEMENTS "enable elements tx code (ON or OFF. default:OFF)" OFF)
option(ENABLE_SWIG_PYTHON "enable the SWIG python interface (ON or OFF. default:OFF)" OFF)
option(ENABLE_SWIG_JAVA "enable the SWIG java (JNI) interface (ON or OFF. default:OFF)" OFF)

if(CMAKE_JS_INC)
option(ENABLE_JS_WRAPPER "enable the Javascript interface wrappers (ON or OFF. default:ON)" ON)
endif()

if(NOT WIN32)
option(ENABLE_EXPORT_ALL "enable export all functions (for testing) (ON or OFF. default:OFF)" OFF)
endif()

if(ENABLE_DEBUG)
set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS $<$<CONFIG:Debug>:DEBUGBUILD>)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -ggdb")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -ggdb")
if(ENABLE_COVERAGE)
set(COLLECT_COVERAGE ON)
endif()
endif()

# common setting
set(WINDOWS_CONFIG_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/windows_config)

# secp256k1/gen_context
set(GEN_CONTEXT_NAME gen_context)

set(ECMULT_STATIC_CONTEXT_H  ${CMAKE_BINARY_DIR}/ecmult_static_context.h)
add_executable(${GEN_CONTEXT_NAME}
    src/secp256k1/src/gen_context.c
    ${WINDOWS_CONFIG_DIRECTORY}/config.h
    ${WINDOWS_CONFIG_DIRECTORY}/libsecp256k1-config.h
)

target_compile_options(${GEN_CONTEXT_NAME}
  PRIVATE
    $<IF:$<C_COMPILER_ID:MSVC>,
      /source-charset:utf-8 /wd4244 /DWALLY_CORE_BUILD /DHAVE_CONFIG_H /DSECP256K1_BUILD,
      -Wall -Wextra -Wno-unused-function
    >
)
target_compile_definitions(${GEN_CONTEXT_NAME}
  PUBLIC
    $<IF:$<C_COMPILER_ID:MSVC>,
      /source-charset:utf-8 /wd4244 /DWALLY_CORE_BUILD /DHAVE_CONFIG_H /DSECP256K1_BUILD,
      -DWALLY_CORE_BUILD=1 -DSECP256K1_BUILD -DHAVE_CONFIG_H
    >
)
target_include_directories(${GEN_CONTEXT_NAME}
  PUBLIC
    ${WINDOWS_CONFIG_DIRECTORY}
    src/secp256k1/include
  PRIVATE
    src/secp256k1
    src/secp256k1/src
    src/secp256k1/contrib
)

set(SECP256K1_GEN_CONTEXT_NAME secp256k1_gen_context)
add_custom_target(${SECP256K1_GEN_CONTEXT_NAME}
  SOURCES ${ECMULT_STATIC_CONTEXT_H}
)

set(WORK_WINDOWS_BINARY_DIR_NAME
  $<IF:$<CONFIG:Debug>,Debug,Release>
)

if(BTCLIB_ROOT_BINARY_DIR AND WIN32)
set(WORK_BINARY_DIR  ${BTCLIB_ROOT_BINARY_DIR})
else()		# BTCLIB_ROOT_BINARY_DIR
set(WORK_BINARY_DIR
  $<IF:$<PLATFORM_ID:Windows>,${CMAKE_BINARY_DIR}/${WORK_WINDOWS_BINARY_DIR_NAME},${CMAKE_BINARY_DIR}>)
endif()		# BTCLIB_ROOT_BINARY_DIR

if(BTCLIB_ROOT_BINARY_DIR)
set(WORK_BINARY_DIR2  ${BTCLIB_ROOT_BINARY_DIR})
else()		# BTCLIB_ROOT_BINARY_DIR
set(WORK_BINARY_DIR2  ${WORK_BINARY_DIR})
endif()		# BTCLIB_ROOT_BINARY_DIR

add_custom_command(OUTPUT  ${ECMULT_STATIC_CONTEXT_H}
  COMMAND echo "[gen_context]" ${WORK_BINARY_DIR}/${GEN_CONTEXT_NAME}
  COMMAND ${WORK_BINARY_DIR}/${GEN_CONTEXT_NAME}
  DEPENDS ${GEN_CONTEXT_NAME}
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1
  VERBATIM
)


# libwally sources
set(LIBWALLY_FILES
    ${WINDOWS_CONFIG_DIRECTORY}/config.h
    ${WINDOWS_CONFIG_DIRECTORY}/libsecp256k1-config.h
    src/aes.c
    src/base58.c
    src/bip32.c
    src/bip38.c
    src/bip39.c
    src/bech32.c
    src/elements.c
    src/hex.c
    src/hmac.c
    src/internal.c
    src/mnemonic.c
    src/pbkdf2.c
    src/script.c
    src/scrypt.c
    src/sign.c
    src/transaction.c
    src/wif.c
    src/wordlist.c
    src/ccan/ccan/crypto/ripemd160/ripemd160.c
    src/ccan/ccan/crypto/sha256/sha256.c
    src/ccan/ccan/crypto/sha512/sha512.c
    src/ccan/ccan/str/hex/hex.c
    src/secp256k1/src/secp256k1.c
    include/wally.hpp
    include/wally_address.h
    include/wally_bip32.h
    include/wally_bip38.h
    include/wally_bip39.h
    include/wally_core.h
    include/wally_crypto.h
    include/wally_elements.h
    include/wally_script.h
    include/wally_transaction.h
    src/secp256k1/include/secp256k1.h
    ${ECMULT_STATIC_CONTEXT_H}
)

# libwally
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
      /LD /source-charset:utf-8 /wd4244 /DWALLY_CORE_BUILD /DHAVE_CONFIG_H /DSECP256K1_BUILD /DUSE_ECMULT_STATIC_PRECOMPUTATION /DECMULT_WINDOW_SIZE=16 $<$<BOOL:$<TARGET_PROPERTY:ENABLE_ELEMENTS>>:/DBUILD_ELEMENTS>,
      -Wall -Wextra -Wno-unused-function
      $<$<BOOL:$<TARGET_PROPERTY:COLLECT_COVERAGE>>:-fprofile-arcs>
      $<$<BOOL:$<TARGET_PROPERTY:COLLECT_COVERAGE>>:-ftest-coverage>
      $<$<BOOL:$<TARGET_PROPERTY:ENABLE_EXPORT_ALL>>:-fvisibility=hidden>
    >
)
target_compile_definitions(${PROJECT_NAME}
  PUBLIC
    $<IF:$<C_COMPILER_ID:MSVC>,
      /source-charset:utf-8 /wd4244 /DUSE_ECMULT_STATIC_PRECOMPUTATION /DWALLY_CORE_BUILD /DHAVE_CONFIG_H /DSECP256K1_BUILD /DECMULT_WINDOW_SIZE=16 $<$<BOOL:$<TARGET_PROPERTY:ENABLE_ELEMENTS>>:/DBUILD_ELEMENTS>,
      -DWALLY_CORE_BUILD=1
      -DSECP256K1_BUILD -DUSE_ECMULT_STATIC_PRECOMPUTATION -DHAVE_CONFIG_H -DECMULT_WINDOW_SIZE=16
      $<$<BOOL:$<TARGET_PROPERTY:ENABLE_ELEMENTS>>:-DBUILD_ELEMENTS>
    >
)
target_include_directories(${PROJECT_NAME}
  PUBLIC
    ${WINDOWS_CONFIG_DIRECTORY}
    include
  PRIVATE
    .
    src
    src/ccan
    src/secp256k1
    src/secp256k1/src
)

if(COLLECT_COVERAGE)
target_link_libraries(${PROJECT_NAME} lcov)
endif()


# node.js build
if(CMAKE_JS_INC AND ENABLE_JS_WRAPPER)
message(STATUS "[CMAKE_JS_INC]=${CMAKE_JS_INC}")
message(STATUS "[CMAKE_JS_LIB]=${CMAKE_JS_LIB}")

if(ENABLE_ELEMENTS)
set(ELEMENTS_OPT "elements")
else()
set(ELEMENTS_OPT "")
endif()
set(OUTPUT_DIR_NAME $<IF:$<CONFIG:Debug>,Debug,Release>)

add_custom_command(OUTPUT  ${CMAKE_BINARY_DIR}/nodejs_wrap.cc
    COMMAND set PYTHONDONTWRITEBYTECODE=1
    COMMAND cd ${CMAKE_CURRENT_SOURCE_DIR}/src
    COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/makewrappers/wrap.py nodejs ${OUTPUT_DIR_NAME} ${ELEMENTS_OPT}
    COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/makewrappers/wrap.py wally ${OUTPUT_DIR_NAME} ${ELEMENTS_OPT}
    COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/nodejs_wrap.cc" ${CMAKE_BINARY_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/wally.js" ${WORK_BINARY_DIR2}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src
    VERBATIM
)

set(NODE_LIBRARY_NAME wallycore)
project(wallycore CXX)

add_library(${NODE_LIBRARY_NAME} SHARED)
target_sources(${NODE_LIBRARY_NAME}
  PRIVATE
    ${LIBWALLY_FILES}
    ${CMAKE_BINARY_DIR}/nodejs_wrap.cc
)

target_compile_options(${NODE_LIBRARY_NAME}
  PRIVATE
    $<IF:$<C_COMPILER_ID:MSVC>,
      /LD /source-charset:utf-8 /wd4244 /wd4251 /DWALLY_CORE_BUILD /DHAVE_CONFIG_H /DSECP256K1_BUILD /DUSE_ECMULT_STATIC_PRECOMPUTATION /DECMULT_WINDOW_SIZE=16 /DSWIG_JAVASCRIPT_BUILD $<$<BOOL:$<TARGET_PROPERTY:ENABLE_ELEMENTS>>:/DBUILD_ELEMENTS>,
      -Wall -Wextra -Wno-unused-function
      $<$<BOOL:$<TARGET_PROPERTY:COLLECT_COVERAGE>>:-fprofile-arcs>
      $<$<BOOL:$<TARGET_PROPERTY:COLLECT_COVERAGE>>:-ftest-coverage>
      $<$<BOOL:$<TARGET_PROPERTY:ENABLE_EXPORT_ALL>>:-fvisibility=hidden>
    >
)
target_compile_definitions(${NODE_LIBRARY_NAME}
  PUBLIC
    $<IF:$<C_COMPILER_ID:MSVC>,
      /source-charset:utf-8 /wd4244 /wd4251 /DWALLY_CORE_BUILD /DHAVE_CONFIG_H /DSECP256K1_BUILD /DUSE_ECMULT_STATIC_PRECOMPUTATION /DECMULT_WINDOW_SIZE=16 /DSWIG_JAVASCRIPT_BUILD $<$<BOOL:$<TARGET_PROPERTY:ENABLE_ELEMENTS>>:/DBUILD_ELEMENTS>,
      -DSECP256K1_BUILD -DUSE_ECMULT_STATIC_PRECOMPUTATION -DHAVE_CONFIG_H -DSWIG_JAVASCRIPT_BUILD -DECMULT_WINDOW_SIZE=16
      $<$<BOOL:$<TARGET_PROPERTY:ENABLE_ELEMENTS>>:-DBUILD_ELEMENTS>
    >
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
  PUBLIC
    ${WINDOWS_CONFIG_DIRECTORY}
    include
  PRIVATE
    .
    src
    src/ccan
    src/secp256k1
    src/secp256k1/src
    node_modules/nan
    ${CMAKE_JS_INC}
)

if(WIN32)
target_link_libraries(${NODE_LIBRARY_NAME} ${CMAKE_JS_LIB} winmm.lib ws2_32.lib)
elseif(APPLE)
target_link_libraries(${NODE_LIBRARY_NAME} ${CMAKE_JS_LIB} pthread)
else()
target_link_libraries(${NODE_LIBRARY_NAME} ${CMAKE_JS_LIB} pthread rt)
endif()

else()	# CMAKE_JS_INC AND ENABLE_JS_WRAPPER

# libwally library
set(WALLYCORE_NAME wallycore)
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
      /LD /source-charset:utf-8 /wd4244 /DWALLY_CORE_BUILD /DHAVE_CONFIG_H /DSECP256K1_BUILD /DUSE_ECMULT_STATIC_PRECOMPUTATION /DECMULT_WINDOW_SIZE=16 $<$<BOOL:$<TARGET_PROPERTY:ENABLE_ELEMENTS>>:/DBUILD_ELEMENTS>,
      -Wall -Wextra -Wno-unused-function
      $<$<BOOL:$<TARGET_PROPERTY:COLLECT_COVERAGE>>:-fprofile-arcs>
      $<$<BOOL:$<TARGET_PROPERTY:COLLECT_COVERAGE>>:-ftest-coverage>
      $<$<BOOL:$<TARGET_PROPERTY:ENABLE_EXPORT_ALL>>:-fvisibility=hidden>
    >
)
target_compile_definitions(${WALLYCORE_NAME}
  PUBLIC
    $<IF:$<C_COMPILER_ID:MSVC>,
      /source-charset:utf-8 /wd4244 /DUSE_ECMULT_STATIC_PRECOMPUTATION /DWALLY_CORE_BUILD /DHAVE_CONFIG_H /DSECP256K1_BUILD /DECMULT_WINDOW_SIZE=16 $<$<BOOL:$<TARGET_PROPERTY:ENABLE_ELEMENTS>>:/DBUILD_ELEMENTS>,
      -DWALLY_CORE_BUILD=1
      -DSECP256K1_BUILD -DUSE_ECMULT_STATIC_PRECOMPUTATION -DHAVE_CONFIG_H -DECMULT_WINDOW_SIZE=16
      $<$<BOOL:$<TARGET_PROPERTY:ENABLE_ELEMENTS>>:-DBUILD_ELEMENTS>
    >
)
target_include_directories(${WALLYCORE_NAME}
  PUBLIC
    ${WINDOWS_CONFIG_DIRECTORY}
    include
  PRIVATE
    .
    src
    src/ccan
    src/secp256k1
    src/secp256k1/src
)

if(COLLECT_COVERAGE)
target_link_libraries(${WALLYCORE_NAME} lcov)
endif()

endif()		# CMAKE_JS_INC AND ENABLE_JS_WRAPPER
