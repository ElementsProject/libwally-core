cmake_minimum_required(VERSION 3.13)

# 書き方が良くないらしいので、以下を参考に書き直す。
# https://qiita.com/shohirose/items/5b406f060cd5557814e9

# libwally layout memo
# - CMakeLists.txt
#   package.json
#   src - wrap_js - nodejs_wrap.cc
# node V12での変更事項：(v8のバージョンアップに伴う影響。何れ修正必要)
#    obj->ToObject()
#     -> Nan::To<v8::Object>(obj).ToLocalChecked() に差し替え。objがinfo[0]でも同様。

# プロジェクト名
project(wally C)
# 絶対パス->相対パス変換
cmake_policy(SET CMP0076 NEW)

# memo：Generator Expressionsにはスペース入れないこと。後方はtrimされないのでスペースも文字認識される
set(CMAKE_VERBOSE_MAKEFILE TRUE)
set(WINDOWS_CONFIG_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/windows_config)

# secp256k1/gen_context
set(GEN_CONTEXT_NAME gen_context)

set(ECMULT_STATIC_CONTEXT_H  ${CMAKE_CURRENT_BINARY_DIR}/ecmult_static_context.h)
add_executable(${GEN_CONTEXT_NAME}
    src/secp256k1/src/gen_context.c
    ${WINDOWS_CONFIG_DIRECTORY}/config.h
    ${WINDOWS_CONFIG_DIRECTORY}/libsecp256k1-config.h
)
#    $<$<C_COMPILER_ID:MSVC>:${WINDOWS_CONFIG_DIRECTORY}/config.h>
#    $<$<C_COMPILER_ID:MSVC>:${WINDOWS_CONFIG_DIRECTORY}/libsecp256k1-config.h>

target_compile_options(${GEN_CONTEXT_NAME}
  PRIVATE
    $<IF:$<C_COMPILER_ID:MSVC>,
      /DWALLY_CORE_BUILD /DHAVE_CONFIG_H /DSECP256K1_BUILD,
      -Wall -Wextra -Wno-unused-function
    >
)
target_compile_definitions(${GEN_CONTEXT_NAME}
  PUBLIC
    $<IF:$<C_COMPILER_ID:MSVC>,
      /DWALLY_CORE_BUILD /DHAVE_CONFIG_H /DSECP256K1_BUILD,
      -DWALLY_CORE_BUILD=1 -DSECP256K1_BUILD -DHAVE_CONFIG_H
    >
)
#    $<$<NOT:$<C_COMPILER_ID:MSVC>>:-DSECP256K1_BUILD -DUSE_ECMULT_STATIC_PRECOMPUTATION -DHAVE_CONFIG_H>
#    $<$<C_COMPILER_ID:MSVC>:/DWALLY_CORE_BUILD /DHAVE_CONFIG_H /DSECP256K1_BUILD>
target_include_directories(${GEN_CONTEXT_NAME}
  PUBLIC
    ${WINDOWS_CONFIG_DIRECTORY}
    src/secp256k1/include
  PRIVATE
    src/secp256k1
    src/secp256k1/src
    src/secp256k1/contrib
)
#    $<$<C_COMPILER_ID:MSVC>:${WINDOWS_CONFIG_DIRECTORY}>

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
  $<IF:$<PLATFORM_ID:Windows>,${CMAKE_CURRENT_BINARY_DIR}/${WORK_WINDOWS_BINARY_DIR_NAME},${CMAKE_CURRENT_BINARY_DIR}>)
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


#set(GEN_CONTEXT_NAME gen_context)

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
#    $<$<C_COMPILER_ID:MSVC>:${WINDOWS_CONFIG_DIRECTORY}/config.h>
#    $<$<C_COMPILER_ID:MSVC>:${WINDOWS_CONFIG_DIRECTORY}/libsecp256k1-config.h>

# libwally
#set(WALLY_NAME wally)
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
      /LD /DWALLY_CORE_BUILD /DHAVE_CONFIG_H /DSECP256K1_BUILD /DBUILD_ELEMENTS /DUSE_ECMULT_STATIC_PRECOMPUTATION /DECMULT_WINDOW_SIZE=16,
      -Wall -Wextra -Wno-unused-function
    >
)
target_compile_definitions(${PROJECT_NAME}
  PUBLIC
    $<IF:$<C_COMPILER_ID:MSVC>,
      /DUSE_ECMULT_STATIC_PRECOMPUTATION /DWALLY_CORE_BUILD /DBUILD_ELEMENTS /DHAVE_CONFIG_H /DSECP256K1_BUILD /DECMULT_WINDOW_SIZE=16,
      -DWALLY_CORE_BUILD=1 -DBUILD_ELEMENTS=1 -DSECP256K1_BUILD -DUSE_ECMULT_STATIC_PRECOMPUTATION -DHAVE_CONFIG_H -DECMULT_WINDOW_SIZE=16
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
#    $<$<CXX_COMPILER_ID:MSVC>:${WINDOWS_CONFIG_DIRECTORY}>

#    src/secp256k1/include
#    src/secp256k1/contrib


# node build
if(CMAKE_JS_INC)
message(STATUS "[CMAKE_JS_INC]=${CMAKE_JS_INC}")
message(STATUS "[CMAKE_JS_LIB]=${CMAKE_JS_LIB}")
# CMAKE_JS_LIBは無くても動くが、環境依存の可能性からそのままにする。

# command
# npm install cmake-js nan --save
# [win] npm config set cmake_js_G "Visual Studio 16 2019"
# [linux] npm config set cmake_js_G "Unix Makefiles"
# node_modules\.bin\cmake-js configure -O build
# node_modules\.bin\cmake-js build -O build
# 

set(ELEMENT_OPT "elements")
set(OUTPUT_DIR_NAME $<IF:$<CONFIG:Debug>,Debug,Release>)

add_custom_command(OUTPUT  ${CMAKE_CURRENT_BINARY_DIR}/nodejs_wrap.cc
    COMMAND set PYTHONDONTWRITEBYTECODE=1
    COMMAND cd ${CMAKE_CURRENT_SOURCE_DIR}/src
    COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/makewrappers/wrap.py nodejs ${OUTPUT_DIR_NAME} ${ELEMENT_OPT}
    COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/makewrappers/wrap.py wally ${OUTPUT_DIR_NAME} ${ELEMENT_OPT}
    COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/nodejs_wrap.cc" ${CMAKE_CURRENT_BINARY_DIR}
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
    ${CMAKE_CURRENT_BINARY_DIR}/nodejs_wrap.cc
)

target_compile_options(${NODE_LIBRARY_NAME}
  PRIVATE
    $<IF:$<C_COMPILER_ID:MSVC>,
      /LD /DWALLY_CORE_BUILD /DHAVE_CONFIG_H /DSECP256K1_BUILD /DBUILD_ELEMENTS /DUSE_ECMULT_STATIC_PRECOMPUTATION /DECMULT_WINDOW_SIZE=16 /DSWIG_JAVASCRIPT_BUILD,
      -Wall -Wextra -Wno-unused-function
    >
)
target_compile_definitions(${NODE_LIBRARY_NAME}
  PUBLIC
    $<IF:$<C_COMPILER_ID:MSVC>,
      /DWALLY_CORE_BUILD /DHAVE_CONFIG_H /DSECP256K1_BUILD /DBUILD_ELEMENTS /DUSE_ECMULT_STATIC_PRECOMPUTATION /DECMULT_WINDOW_SIZE=16 /DSWIG_JAVASCRIPT_BUILD,
      -DBUILD_ELEMENTS=1 -DSECP256K1_BUILD -DUSE_ECMULT_STATIC_PRECOMPUTATION -DHAVE_CONFIG_H -DSWIG_JAVASCRIPT_BUILD -DECMULT_WINDOW_SIZE=16
    >
)

#if(WIN32)
#  target_link_libraries(${NODE_LIBRARY_NAME} "winmm.lib" "ws2_32.lib")
#elseif(UNIX)
#  target_link_libraries(${NODE_LIBRARY_NAME} pthread rt)
#endif()

# ライブラリフォルダの指定
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
  PRIVATE ${CMAKE_JS_INC}
)
#    $<$<CXX_COMPILER_ID:MSVC>:${WINDOWS_CONFIG_DIRECTORY}>

# You should add this line in every CMake.js based project
#set(NODE_LINK_LIBRARY1 $<IF:$<PLATFORM_ID:Windows>,winmm.lib ws2_32.lib,pthread rt>)
#set(NODE_LINK_LIBRARY2 $<IF:$<PLATFORM_ID:Windows>,winmm.lib ws2_32.lib,pthread rt>)
if(WIN32)
target_link_libraries(${NODE_LIBRARY_NAME} ${CMAKE_JS_LIB}
  winmm.lib ws2_32.lib
)
else()
target_link_libraries(${NODE_LIBRARY_NAME} ${CMAKE_JS_LIB}
  pthread rt
)
endif()

else()	# CMAKE_JS_INC

# libwally shared library
set(WALLYCORE_NAME wallycore)
add_library(${WALLYCORE_NAME} SHARED)
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
      /LD /DWALLY_CORE_BUILD /DHAVE_CONFIG_H /DSECP256K1_BUILD /DBUILD_ELEMENTS /DUSE_ECMULT_STATIC_PRECOMPUTATION /DECMULT_WINDOW_SIZE=16,
      -Wall -Wextra -Wno-unused-function
    >
)
target_compile_definitions(${WALLYCORE_NAME}
  PUBLIC
    $<IF:$<C_COMPILER_ID:MSVC>,
      /DUSE_ECMULT_STATIC_PRECOMPUTATION /DWALLY_CORE_BUILD /DBUILD_ELEMENTS /DHAVE_CONFIG_H /DSECP256K1_BUILD /DECMULT_WINDOW_SIZE=16,
      -DWALLY_CORE_BUILD=1 -DBUILD_ELEMENTS=1 -DSECP256K1_BUILD -DUSE_ECMULT_STATIC_PRECOMPUTATION -DHAVE_CONFIG_H -DECMULT_WINDOW_SIZE=16
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

endif()		# CMAKE_JS_INC
