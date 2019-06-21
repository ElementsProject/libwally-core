cmake_minimum_required(VERSION 3.13)

# AC_INIT([libwallycore],[0.7.1])
set(PACKAGE_VERSION   0.7.1)

# wally project
project(wally C)
cmake_policy(SET CMP0076 NEW)
cmake_policy(SET CMP0086 NEW)
set(CMAKE_VERBOSE_MAKEFILE TRUE)

####################
# options
####################
if(CMAKE_JS_INC)
option(ENABLE_SHARED "enable shared library (ON or OFF. default:ON)" ON)
else()
option(ENABLE_SHARED "enable shared library (ON or OFF. default:OFF)" OFF)
endif()
option(ENABLE_DEBUG "enable debugging (ON or OFF. default:OFF)" OFF)
option(ENABLE_ELEMENTS "enable elements tx code (ON or OFF. default:OFF)" OFF)
option(ENABLE_SWIG_PYTHON "enable the SWIG python interface (ON or OFF. default:OFF)" OFF)
option(ENABLE_SWIG_JAVA "enable the SWIG java (JNI) interface (ON or OFF. default:OFF)" OFF)

if(CMAKE_JS_INC)
option(ENABLE_JS_WRAPPER "enable the Javascript interface wrappers (ON or OFF. default:ON)" ON)
endif()

if(NOT WIN32)
option(ENABLE_TESTS "enable code tests (ON or OFF. default:ON)" ON)
option(ENABLE_COVERAGE "enable code coverage (ON or OFF. default:OFF)" OFF)
option(ENABLE_EXPORT_ALL "enable export all functions (for testing) (ON or OFF. default:OFF)" OFF)
set(ENABLE_EXPORT_ALL_OPT "")
else()
set(ENABLE_EXPORT_ALL_OPT -fvisibility=hidden)
endif()

if(ENABLE_DEBUG)
set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS $<$<CONFIG:Debug>:DEBUGBUILD>)
if(MSVC)
set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} /Od /Zi")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /Od /Zi")
else()
set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -O0 -ggdb")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -ggdb")
endif()
endif()

####################
# common setting
####################
set(WORK_WINDOWS_BINARY_DIR_NAME  $<IF:$<CONFIG:Debug>,Debug,Release>)
if(NOT BTCLIB_OBJ_BINARY_DIR)
set(BTCLIB_OBJ_BINARY_DIR   ${CMAKE_BINARY_DIR}/${WORK_WINDOWS_BINARY_DIR_NAME})
set(BTCLIB_ROOT_BINARY_DIR
  $<IF:$<PLATFORM_ID:Windows>,${BTCLIB_OBJ_BINARY_DIR},${CMAKE_BINARY_DIR}>)
endif()
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY  ${BTCLIB_OBJ_BINARY_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY  ${BTCLIB_ROOT_BINARY_DIR})
set(WORK_BINARY_DIR  ${BTCLIB_ROOT_BINARY_DIR})
set(BINARY_OUTPUT_DIR  ${BTCLIB_ROOT_BINARY_DIR})

if(NOT ENABLE_ELEMENTS)
set(ELEMENTS_COMP_OPT "")
else()
set(ELEMENTS_COMP_OPT  $<IF:$<C_COMPILER_ID:MSVC>,/DBUILD_ELEMENTS,BUILD_ELEMENTS>)
endif()

####################
# wally common setting
####################
set(WINDOWS_CONFIG_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/windows_config)

if(ENABLE_DEBUG AND ENABLE_COVERAGE)
set(COLLECT_COVERAGE ON)
set(PROFILE_ARCS_OPT -fprofile-arcs)
set(TEST_COVERAGE_OPT -ftest-coverage)
else()
set(PROFILE_ARCS_OPT  "")
set(TEST_COVERAGE_OPT "")
endif()

if(PYTHONHOME)
set(INCLUDE_PYTHONHOME  ${PYTHONHOME}/include)
else()
set(INCLUDE_PYTHONHOME  "")
endif()

####################
# secp256k1/gen_context
####################
set(GEN_CONTEXT_NAME gen_context)

set(ECMULT_STATIC_CONTEXT_H  ${CMAKE_BINARY_DIR}/ecmult_static_context.h)
set(SRC_ECMULT_STATIC_CONTEXT_H  ${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1/src/ecmult_static_context.h)
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
  PRIVATE
    $<IF:$<C_COMPILER_ID:MSVC>,
      /source-charset:utf-8 /wd4244 /DWALLY_CORE_BUILD /DHAVE_CONFIG_H /DSECP256K1_BUILD,
      -DWALLY_CORE_BUILD=1 -DSECP256K1_BUILD -DHAVE_CONFIG_H
    >
)
target_include_directories(${GEN_CONTEXT_NAME}
  PUBLIC
    src/secp256k1/include
  PRIVATE
    ${WINDOWS_CONFIG_DIRECTORY}
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

add_custom_command(OUTPUT  ${ECMULT_STATIC_CONTEXT_H}
  COMMAND echo "[gen_context]" ${WORK_BINARY_DIR}/${GEN_CONTEXT_NAME}
  COMMAND ${WORK_BINARY_DIR}/${GEN_CONTEXT_NAME}
  COMMAND ${CMAKE_COMMAND} -E copy_if_different ${SRC_ECMULT_STATIC_CONTEXT_H} ${ECMULT_STATIC_CONTEXT_H}
  COMMAND ${CMAKE_COMMAND} -E compare_files ${SRC_ECMULT_STATIC_CONTEXT_H} ${ECMULT_STATIC_CONTEXT_H}
  COMMAND ${CMAKE_COMMAND} -E remove -f ${SRC_ECMULT_STATIC_CONTEXT_H}
  DEPENDS ${GEN_CONTEXT_NAME}
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1
  VERBATIM
)


####################
# libwally sources
####################
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
    src/bip32_int.h
    src/transaction_int.h
    ${ECMULT_STATIC_CONTEXT_H}
)

####################
# libwally
####################
set(WALLY_PROJECT_NAME wally)
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
      /LD /source-charset:utf-8 /wd4244 /DWALLY_CORE_BUILD /DHAVE_CONFIG_H /DSECP256K1_BUILD /DUSE_ECMULT_STATIC_PRECOMPUTATION /DECMULT_WINDOW_SIZE=16 ${ELEMENTS_COMP_OPT},
      -Wall -Wextra -Wno-unused-function
      ${PROFILE_ARCS_OPT} ${TEST_COVERAGE_OPT} ${ENABLE_EXPORT_ALL_OPT}
    >
)
target_compile_definitions(${PROJECT_NAME}
  PRIVATE
    ${ELEMENTS_COMP_OPT}
    $<IF:$<C_COMPILER_ID:MSVC>,
      /source-charset:utf-8 /wd4244 /DUSE_ECMULT_STATIC_PRECOMPUTATION /DWALLY_CORE_BUILD /DHAVE_CONFIG_H /DSECP256K1_BUILD /DECMULT_WINDOW_SIZE=16,
      -DWALLY_CORE_BUILD=1
      -DSECP256K1_BUILD -DUSE_ECMULT_STATIC_PRECOMPUTATION -DHAVE_CONFIG_H -DECMULT_WINDOW_SIZE=16
    >
)
target_include_directories(${PROJECT_NAME}
  PUBLIC
    include
    src/secp256k1/include
  PRIVATE
    ${WINDOWS_CONFIG_DIRECTORY}
    .
    src
    src/ccan
    src/secp256k1
    src/secp256k1/src
    ${CMAKE_BINARY_DIR}
)

if(COLLECT_COVERAGE)
target_link_libraries(${PROJECT_NAME} lcov)
endif()


####################
# node.js build
####################
if(CMAKE_JS_INC AND ENABLE_JS_WRAPPER)
message(STATUS "[CMAKE_JS_INC]=${CMAKE_JS_INC}")

if(ENABLE_ELEMENTS)
set(ELEMENTS_OPT "elements")
else()
set(ELEMENTS_OPT "")
endif()
set(OUTPUT_DIR_NAME $<IF:$<CONFIG:Debug>,Debug,Release>)

set(NODEJS_WRAP_CC_NAME nodejs_wrap_cc)
add_custom_target(${NODEJS_WRAP_CC_NAME} SOURCES ${CMAKE_BINARY_DIR}/nodejs_wrap.cc)

add_custom_command(OUTPUT  ${CMAKE_BINARY_DIR}/nodejs_wrap.cc
    COMMAND set PYTHONDONTWRITEBYTECODE=1
    COMMAND cd ${CMAKE_CURRENT_SOURCE_DIR}/src
    COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/makewrappers/wrap.py nodejs ${OUTPUT_DIR_NAME} ${ELEMENTS_OPT}
    COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/makewrappers/wrap.py wally ${OUTPUT_DIR_NAME} ${ELEMENTS_OPT}
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/nodejs_wrap.cc" ${CMAKE_BINARY_DIR}/nodejs_wrap.cc
    COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/src/wrap_js/wally.js" ${BINARY_OUTPUT_DIR}
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
      /LD /source-charset:utf-8 /wd4244 /wd4251 /DWALLY_CORE_BUILD /DHAVE_CONFIG_H /DSECP256K1_BUILD /DUSE_ECMULT_STATIC_PRECOMPUTATION /DECMULT_WINDOW_SIZE=16 /DSWIG_JAVASCRIPT_BUILD ${ELEMENTS_COMP_OPT},
      -Wall -Wextra -Wno-unused-function
      ${PROFILE_ARCS_OPT} ${TEST_COVERAGE_OPT} ${ENABLE_EXPORT_ALL_OPT}
    >
)
target_compile_definitions(${NODE_LIBRARY_NAME}
  PRIVATE
    ${ELEMENTS_COMP_OPT}
    $<IF:$<C_COMPILER_ID:MSVC>,
      /source-charset:utf-8 /wd4244 /wd4251 /DWALLY_CORE_BUILD /DHAVE_CONFIG_H /DSECP256K1_BUILD /DUSE_ECMULT_STATIC_PRECOMPUTATION /DECMULT_WINDOW_SIZE=16 /DSWIG_JAVASCRIPT_BUILD,
      -DSECP256K1_BUILD -DUSE_ECMULT_STATIC_PRECOMPUTATION -DHAVE_CONFIG_H -DSWIG_JAVASCRIPT_BUILD -DECMULT_WINDOW_SIZE=16
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
  PRIVATE
    include
    src/secp256k1/include
    ${WINDOWS_CONFIG_DIRECTORY}
    .
    src
    src/ccan
    src/secp256k1
    src/secp256k1/src
    ${CMAKE_BINARY_DIR}
    node_modules/nan
    ${CMAKE_JS_INC}
)

target_link_libraries(${NODE_LIBRARY_NAME}
  PRIVATE $<$<BOOL:$<CXX_COMPILER_ID:MSVC>>:winmm.lib>
  PRIVATE $<$<BOOL:$<CXX_COMPILER_ID:MSVC>>:ws2_32.lib>
  PRIVATE $<$<BOOL:$<CXX_COMPILER_ID:GNU>>:-static-libgcc>
  PRIVATE $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-static-libstdc++>
  PRIVATE $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:pthread>
  PRIVATE $<IF:$<OR:$<PLATFORM_ID:Darwin>,$<CXX_COMPILER_ID:MSVC>>,,rt>
  PRIVATE
    ${CMAKE_JS_LIB}
)

else()	# CMAKE_JS_INC AND ENABLE_JS_WRAPPER

####################
# libwally library
####################
set(WALLYCORE_NAME wallycore)
set(WALLY_PROJECT_NAME ${WALLYCORE_NAME})
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
      /LD /source-charset:utf-8 /wd4244 /DWALLY_CORE_BUILD /DHAVE_CONFIG_H /DSECP256K1_BUILD /DUSE_ECMULT_STATIC_PRECOMPUTATION /DECMULT_WINDOW_SIZE=16 ${ELEMENTS_COMP_OPT},
      -Wall -Wextra -Wno-unused-function
      ${PROFILE_ARCS_OPT} ${TEST_COVERAGE_OPT} ${ENABLE_EXPORT_ALL_OPT}
    >
)
target_compile_definitions(${WALLYCORE_NAME}
  PRIVATE
    ${ELEMENTS_COMP_OPT}
    $<IF:$<C_COMPILER_ID:MSVC>,
      /source-charset:utf-8 /wd4244 /DUSE_ECMULT_STATIC_PRECOMPUTATION /DWALLY_CORE_BUILD /DHAVE_CONFIG_H /DSECP256K1_BUILD /DECMULT_WINDOW_SIZE=16,
      -DWALLY_CORE_BUILD=1
      -DSECP256K1_BUILD -DUSE_ECMULT_STATIC_PRECOMPUTATION -DHAVE_CONFIG_H -DECMULT_WINDOW_SIZE=16
    >
)
target_include_directories(${WALLYCORE_NAME}
  PRIVATE
    include
    src/secp256k1/include
    ${WINDOWS_CONFIG_DIRECTORY}
    .
    src
    src/ccan
    src/secp256k1
    src/secp256k1/src
    ${CMAKE_BINARY_DIR}
)

if(COLLECT_COVERAGE)
target_link_libraries(${WALLYCORE_NAME} lcov)
endif()

endif()		# CMAKE_JS_INC AND ENABLE_JS_WRAPPER


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
project(wallycore_swig_python C)
set(PYTHON_WALLY_FILE ${CMAKE_BINARY_DIR}/wallycore.py)
set(PYTHON_WALLY_INIT_FILE ${CMAKE_BINARY_DIR}/__init__.py)

set_property(SOURCE src/swig_python/swig.i PROPERTY SWIG_MODULE_NAME wallycore)
set(INTERFACE_FILES  src/swig_python/swig.i)

find_package(PythonLibs REQUIRED)
find_package(SWIG REQUIRED)

include(${SWIG_USE_FILE})
include(GenerateExportHeader)

# swig_python_wrap.c
swig_add_library(${WALLY_SWIG_PYTHON_NAME}
    LANGUAGE python
    OUTFILE_DIR ${CMAKE_BINARY_DIR}
    SOURCES ${INTERFACE_FILES} ${LIBWALLY_FILES}
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
    ${WINDOWS_CONFIG_DIRECTORY}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ccan
    ${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1
    ${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1/src
    ${CMAKE_BINARY_DIR}
    ${SWIG_PATH}/Lib/python
    ${CMAKE_CURRENT_SOURCE_DIR}/src/swig_python
    ${INCLUDE_PYTHONHOME}
)
target_include_directories(${WALLY_SWIG_PYTHON_NAME}
  PRIVATE
    ${WINDOWS_CONFIG_DIRECTORY}
    include
    .
    src
    src/ccan
    src/secp256k1
    src/secp256k1/src
    ${CMAKE_BINARY_DIR}
    ${SWIG_PATH}/Lib/python
    src/swig_python
    ${INCLUDE_PYTHONHOME}
)

# SWIG_INCLUDE_DIRECTORIES
set_property(TARGET ${WALLY_SWIG_PYTHON_NAME} PROPERTY SWIG_COMPILE_DEFINITIONS 
    SWIG_PYTHON_BUILD USE_SWIG_PYTHON WALLY_CORE_BUILD SECP256K1_BUILD USE_ECMULT_STATIC_PRECOMPUTATION HAVE_CONFIG_H ${ELEMENTS_COMP_OPT}
)
set_property(TARGET ${WALLY_SWIG_PYTHON_NAME} PROPERTY SWIG_COMPILE_OPTIONS 
    -DECMULT_WINDOW_SIZE=16 -DSWIG_PYTHON_BUILD -DUSE_SWIG_PYTHON -DWALLY_CORE_BUILD -DSECP256K1_BUILD -DUSE_ECMULT_STATIC_PRECOMPUTATION -DHAVE_CONFIG_H ${ELEMENTS_COMP_OPT}
)
# swig_link_libraries(${WALLY_SWIG_PYTHON_NAME} ${PYTHON_LIBRARIES} wally)
target_link_libraries(${WALLY_SWIG_PYTHON_NAME}
  PRIVATE $<$<NOT:$<C_COMPILER_ID:MSVC>>:-static-libgcc> ${PYTHON_LIBRARIES}
  INTERFACE wally)

target_compile_options(${WALLY_SWIG_PYTHON_NAME}
  PRIVATE
    $<IF:$<C_COMPILER_ID:MSVC>,
      /LD /source-charset:utf-8 /wd4244 /DWALLY_CORE_BUILD /DHAVE_CONFIG_H /DSECP256K1_BUILD /DUSE_ECMULT_STATIC_PRECOMPUTATION /DECMULT_WINDOW_SIZE=16 /DUSE_SWIG_PYTHON /DSWIG_PYTHON_BUILD /I"${INCLUDE_PYTHONHOME}" ${ELEMENTS_COMP_OPT},
      -Wall -Wextra -Wno-unused-function
    >
)
target_compile_definitions(${WALLY_SWIG_PYTHON_NAME}
  PRIVATE
    ${ELEMENTS_COMP_OPT}
    $<IF:$<C_COMPILER_ID:MSVC>,
      /source-charset:utf-8 /wd4244 /DUSE_ECMULT_STATIC_PRECOMPUTATION /DWALLY_CORE_BUILD /DHAVE_CONFIG_H /DSECP256K1_BUILD /DECMULT_WINDOW_SIZE=16 /DUSE_SWIG_PYTHON /DSWIG_PYTHON_BUILD /I"${INCLUDE_PYTHONHOME}",
      -DWALLY_CORE_BUILD=1 -DSECP256K1_BUILD -DUSE_ECMULT_STATIC_PRECOMPUTATION -DHAVE_CONFIG_H -DECMULT_WINDOW_SIZE=16
    >
)

# %SWIG_PATH%\swig -python -Isrc -I%SWIG_PATH%\Lib\python -DBUILD_ELEMENTS=1 src\swig_python\swig.i
# copy src\swig_python\wallycore.py + src\swig_python\python_extra.py_in src\swig_python\wallycore\__init__.py /B
# del src\swig_python\wallycore.py

#     $(GNU_SED) -i 's/_wallycore/libwallycore/g' swig_python/wallycore.py $@ && \
#     cat swig_python/wallycore.py swig_python/python_extra.py_in > swig_python/wallycore/__init__.py && \

set(GEN_PYTHON_FILE ${CMAKE_CURRENT_SOURCE_DIR}/src/swig_python/python_extra.py_in)

add_custom_target(swig_python_cmd  ALL
    COMMAND echo "[generate python file]"
    COMMAND echo "copy /Y /B ${PYTHON_WALLY_FILE} + ${GEN_PYTHON_FILE} ${PYTHON_WALLY_INIT_FILE} /B"
    COMMAND COPY /Y /B "${PYTHON_WALLY_FILE}" + "${GEN_PYTHON_FILE}" "${PYTHON_WALLY_INIT_FILE}" /B
    DEPENDS ${WALLY_SWIG_PYTHON_NAME}
    VERBATIM
    USES_TERMINAL
)

# if IS_OSX
# # Python requires the shared library have a .so extension for 'import'
# .libs/libwallycore.so:
# 	$(AM_V_at)ln -s libwallycore.dylib .libs/libwallycore.so
# SWIG_PYTHON_TEST_DEPS = .libs/libwallycore.so
# endif

# noinst_LTLIBRARIES += libswig_python.la
# libswig_python_la_CFLAGS = -I$(top_srcdir) $(AM_CFLAGS) $(SWIG_PYTHON_CPPFLAGS) $(SWIG_WARN_CFLAGS) $(NOALIAS_CFLAGS)
# libswig_python_la_LIBADD = $(PYTHON_LIBS)

endif()		# USE_SWIG_PYTHON


####################
# install & export
####################
set(prefix            ${CMAKE_INSTALL_PREFIX})
set(exec_prefix       ${prefix})
set(libdir            ${exec_prefix}/lib)
set(includedir        ${prefix}/include)
include(GNUInstallDirs)

configure_file(src/wallycore.pc.in  wallycore.pc  @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/wallycore.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

install(TARGETS       ${WALLY_PROJECT_NAME}
        EXPORT        wallycore-export
        ARCHIVE       DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY       DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
export(TARGETS ${WALLY_PROJECT_NAME}
       APPEND FILE ${PROJECT_BINARY_DIR}/${WALLY_PROJECT_NAME}-export.cmake
       EXPORT_LINK_INTERFACE_LIBRARIES)

install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
        FILES_MATCHING REGEX "/[^/]*\\.(h|hpp)$")
install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/src/secp256k1/include/"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
        FILES_MATCHING PATTERN "*.h")
