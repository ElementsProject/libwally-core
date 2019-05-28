cmake_minimum_required(VERSION 3.13)

# 書き方が良くないらしいので、以下を参考に書き直す。
# https://qiita.com/shohirose/items/5b406f060cd5557814e9

# libwally layout memo
# - CMakeLists.txt
#   package.json
#   src - wrap_js - nodejs_wrap.cc
# 変更事項：
#    obj->ToObject()
#     -> Nan::To<v8::Object>(obj).ToLocalChecked() に差し替え。objがinfo[0]でも同様。

# プロジェクト名
project(wally C)
# 絶対パス->相対パス変換
cmake_policy(SET CMP0076 NEW)

# memo：Generator Expressionsにはスペース入れないこと。後方はtrimされないのでスペースも文字認識される
set(CMAKE_VERBOSE_MAKEFILE TRUE)
set(WINDOWS_CONFIG_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/windows_config)

# cl /DUSE_ECMULT_STATIC_PRECOMPUTATION /DWALLY_CORE_BUILD /DHAVE_CONFIG_H /DSECP256K1_BUILD /I%LIBWALLY_DIR%\src\wrap_js\windows_config /I%LIBWALLY_DIR% /I%LIBWALLY_DIR%\src /I%LIBWALLY_DIR%\include /I%LIBWALLY_DIR%\src\ccan /I%LIBWALLY_DIR%\src\secp256k1 /Zi /LD src/aes.c src/base58.c src/bip32.c src/bip38.c src/bip39.c src/elements.c src/hex.c src/hmac.c src/internal.c src/mnemonic.c src/pbkdf2.c src/scrypt.c src/sign.c src/wif.c src/wordlist.c src/ccan/ccan/crypto/ripemd160/ripemd160.c src/ccan/ccan/crypto/sha256/sha256.c src/ccan/ccan/crypto/sha512/sha512.c src\ccan\ccan\str\hex\hex_.c src/secp256k1/src/secp256k1.c /Fewally.dll

# cl /c /ID:\workspace\dllmktest\cmake_test\test\libwally\src\wrap_js\windows_config /ID:\workspace\dllmktest\cmake_test\test\libwally\include /ID:\workspace\dllmktest\cmake_test\test\libwally\. /ID:\workspace\dllmktest\cmake_test\test\libwally\src /ID:\workspace\dllmktest\cmake_test\test\libwally\src\ccan /ID:\workspace\dllmktest\cmake_test\test\libwally\src\secp256k1 /Zi /W3 /WX- /diagnostics:classic /Od /Ob0 /D WIN32 /D _WINDOWS /D /DUSE_ECMULT_STATIC_PRECOMPUTATION /D /DWALLY_CORE_BUILD /D /DHAVE_CONFIG_H /D /DSECP256K1_BUILD /D "CMAKE_INTDIR=\"Debug\"" /D wally_EXPORTS /D _WINDLL /D _MBCS /Gm- /RTC1 /MDd /GS /fp:precise /Zc:wchar_t /Zc:forScope /Zc:inline /Fo"wally.dir\Debug\/src/ccan/ccan/str/hex/hex.c.obj" /Fd"wally.dir\Debug\vc142.pdb" /Gd /TC /errorReport:queue  /LD D:\workspace\dllmktest\cmake_test\test\libwally\src\ccan\ccan\str\hex\hex.c

#set(ECMULT_STATIC_CONTEXT_H  ${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1/src/ecmult_static_context.h)
#add_subdirectory(src/secp256k1)

# memo：Generator Expressionsにはスペース入れないこと。後方はtrimされないのでスペースも文字認識される
set(CMAKE_VERBOSE_MAKEFILE TRUE)
set(WINDOWS_CONFIG_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/windows_config)

# secp256k1/gen_context
set(GEN_CONTEXT_NAME gen_context)

set(ECMULT_STATIC_CONTEXT_H  ${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1/src/ecmult_static_context.h)
add_executable(${GEN_CONTEXT_NAME}
    src/secp256k1/src/gen_context.c
    $<$<C_COMPILER_ID:MSVC>:${WINDOWS_CONFIG_DIRECTORY}/config.h>
    $<$<C_COMPILER_ID:MSVC>:${WINDOWS_CONFIG_DIRECTORY}/libsecp256k1-config.h>
)
target_compile_options(${GEN_CONTEXT_NAME}
  PRIVATE
    $<$<C_COMPILER_ID:Clang>:-Wall -Wextra -Wno-unused-function>
    $<$<C_COMPILER_ID:GCC>:-Wall -Wextra -Wno-unused-function>
    $<$<C_COMPILER_ID:MSVC>:>
)
target_compile_definitions(${GEN_CONTEXT_NAME}
  PUBLIC
    $<$<C_COMPILER_ID:Clang>:-DSECP256K1_BUILD -DUSE_ECMULT_STATIC_PRECOMPUTATION -DHAVE_CONFIG_H>
    $<$<C_COMPILER_ID:GCC>:-DSECP256K1_BUILD -DUSE_ECMULT_STATIC_PRECOMPUTATION -DHAVE_CONFIG_H>
    $<$<C_COMPILER_ID:MSVC>:/DWALLY_CORE_BUILD /DHAVE_CONFIG_H /DSECP256K1_BUILD>
)
target_include_directories(${GEN_CONTEXT_NAME}
  PUBLIC
    $<$<C_COMPILER_ID:MSVC>:${WINDOWS_CONFIG_DIRECTORY}>
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
set(WORK_BINARY_DIR
  $<IF:$<PLATFORM_ID:Windows>,${CMAKE_CURRENT_BINARY_DIR}/${WORK_WINDOWS_BINARY_DIR_NAME},${CMAKE_CURRENT_BINARY_DIR}>)
#set(WORK_ECMULT_STATIC_CONTEXT_H  ${WORK_BINARY_DIR}/src/secp256k1/src/ecmult_static_context.h)

add_custom_command(OUTPUT  ${ECMULT_STATIC_CONTEXT_H}
  COMMAND echo "[gen_context]" ${WORK_BINARY_DIR}/${GEN_CONTEXT_NAME}
  COMMAND ${WORK_BINARY_DIR}/${GEN_CONTEXT_NAME}
  DEPENDS ${GEN_CONTEXT_NAME}
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1
  VERBATIM
)


#set(GEN_CONTEXT_NAME gen_context)

# libwally
#set(WALLY_NAME wally)
add_library(${PROJECT_NAME} SHARED)
target_sources(${PROJECT_NAME}
  PRIVATE
    $<$<C_COMPILER_ID:MSVC>:${WINDOWS_CONFIG_DIRECTORY}/config.h>
    $<$<C_COMPILER_ID:MSVC>:${WINDOWS_CONFIG_DIRECTORY}/libsecp256k1-config.h>
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
#add_dependencies(${PROJECT_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1/src/ecmult_static_context.h)

#    src/secp256k1/src/ecmult_static_context.h
target_compile_options(${PROJECT_NAME}
  PRIVATE
    $<$<CXX_COMPILER_ID:Clang>:-Wall -Wextra -Wno-unused-function>
    $<$<CXX_COMPILER_ID:GCC>:-Wall -Wextra -Wno-unused-function>
    $<$<CXX_COMPILER_ID:MSVC>:/LD /DWALLY_CORE_BUILD /DHAVE_CONFIG_H /DSECP256K1_BUILD /DECMULT_WINDOW_SIZE=16>
)
target_compile_definitions(${PROJECT_NAME}
  PUBLIC
    $<$<CXX_COMPILER_ID:Clang>:-DWALLY_CORE_BUILD=1 -DBUILD_ELEMENTS=1 -DSECP256K1_BUILD -DUSE_ECMULT_STATIC_PRECOMPUTATION -DHAVE_CONFIG_H -DECMULT_WINDOW_SIZE=16>
    $<$<CXX_COMPILER_ID:GCC>:-DWALLY_CORE_BUILD=1 -DBUILD_ELEMENTS=1 -DSECP256K1_BUILD -DUSE_ECMULT_STATIC_PRECOMPUTATION -DHAVE_CONFIG_H -DECMULT_WINDOW_SIZE=16>
    $<$<CXX_COMPILER_ID:MSVC>:/DUSE_ECMULT_STATIC_PRECOMPUTATION /DWALLY_CORE_BUILD /DBUILD_ELEMENTS /DHAVE_CONFIG_H /DSECP256K1_BUILD /DECMULT_WINDOW_SIZE=16>
)
target_include_directories(${PROJECT_NAME}
  PUBLIC
    $<$<CXX_COMPILER_ID:MSVC>:${WINDOWS_CONFIG_DIRECTORY}>
    include
  PRIVATE
    .
    src
    src/ccan
    src/secp256k1
)
#    src/secp256k1/include
#    src/secp256k1/contrib


# node build
if(CMAKE_JS_LIB)

# command
# npm install cmake-js nan --save
# npm config set cmake_js_G "Visual Studio 16 2019"
# node_modules\.bin\cmake-js configure
# node_modules\.bin\cmake-js build
# 

set(ELEMENT_OPT "elements")
set(OUTPUT_DIR_NAME $<IF:$<CONFIG:Debug>,Debug,Release>)
set(COPY_CMD $<IF:$<PLATFORM_ID:Windows>,copy /Y,cp -f>)
#set(COPY_OPT $<IF:$<PLATFORM_ID:Windows>,/Y,-f>)

add_custom_command(OUTPUT  ${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/nodejs_wrap.cc
    COMMAND set PYTHONDONTWRITEBYTECODE=1
    COMMAND cd ${CMAKE_CURRENT_SOURCE_DIR}/src
    COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/makewrappers/wrap.py nodejs ${OUTPUT_DIR_NAME} ${ELEMENT_OPT}
    COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/makewrappers/wrap.py wally ${OUTPUT_DIR_NAME} ${ELEMENT_OPT}
    COMMAND echo ${COPY_CMD} "${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/wally.js" ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/wally.js" ${CMAKE_CURRENT_BINARY_DIR}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src
    VERBATIM
)
#    COMMAND ${COPY_CMD} "${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/wally.js" ${CMAKE_CURRENT_BINARY_DIR}

set(NODE_LIBRARY_NAME wallycore)
project(wallycore CXX)

add_library(${NODE_LIBRARY_NAME} SHARED)
target_sources(${NODE_LIBRARY_NAME}
  PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:${WINDOWS_CONFIG_DIRECTORY}/config.h>
    $<$<CXX_COMPILER_ID:MSVC>:${WINDOWS_CONFIG_DIRECTORY}/libsecp256k1-config.h>
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
    ${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/nodejs_wrap.cc
    ${ECMULT_STATIC_CONTEXT_H}
)
target_compile_options(${NODE_LIBRARY_NAME}
  PRIVATE
    $<$<CXX_COMPILER_ID:Clang>:-Wall -Wextra -Wno-unused-function>
    $<$<CXX_COMPILER_ID:GCC>:-Wall -Wextra -Wno-unused-function>
    $<$<CXX_COMPILER_ID:MSVC>:/LD /DBUILD_ELEMENTS /DHAVE_CONFIG_H /DSECP256K1_BUILD /DSWIG_JAVASCRIPT_BUILD /DECMULT_WINDOW_SIZE=16>
)
target_compile_definitions(${NODE_LIBRARY_NAME}
  PUBLIC
    $<$<CXX_COMPILER_ID:Clang>:-DBUILD_ELEMENTS=1 -DSECP256K1_BUILD -DUSE_ECMULT_STATIC_PRECOMPUTATION -DHAVE_CONFIG_H -DSWIG_JAVASCRIPT_BUILD -DECMULT_WINDOW_SIZE=16>
    $<$<CXX_COMPILER_ID:GCC>:-DBUILD_ELEMENTS=1 -DSECP256K1_BUILD -DUSE_ECMULT_STATIC_PRECOMPUTATION -DHAVE_CONFIG_H -DSWIG_JAVASCRIPT_BUILD -DECMULT_WINDOW_SIZE=16>
    $<$<CXX_COMPILER_ID:MSVC>:/DUSE_ECMULT_STATIC_PRECOMPUTATION /DBUILD_ELEMENTS /DHAVE_CONFIG_H /DSECP256K1_BUILD /DSWIG_JAVASCRIPT_BUILD /DECMULT_WINDOW_SIZE=16>
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
    $<$<CXX_COMPILER_ID:MSVC>:${WINDOWS_CONFIG_DIRECTORY}>
    include
  PRIVATE
    .
    src
    src/ccan
    src/secp256k1
    node_modules/nan
  PRIVATE ${CMAKE_JS_INC}
)

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
#  $<$<NOT:$<PLATFORM_ID:APPLE>>:"pthread" "rt">

endif()		# CMAKE_JS_LIB
