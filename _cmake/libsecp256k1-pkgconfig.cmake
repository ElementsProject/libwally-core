### Update libsecp256k1.pc to fix its installation prefix

cmake_path(ABSOLUTE_PATH CMAKE_INSTALL_PREFIX OUTPUT_VARIABLE _absolute_prefix )
find_file(_secp_pkg_cfg libsecp256k1.pc
    PATHS ${_absolute_prefix}
    PATH_SUFFIXES lib/pkgconfig
)
if(NOT _secp_pkg_cfg)
    message(FATAL_ERROR "pkg-config file for libsecp256k1 not found, please check your cmake build system")
endif()

file(STRINGS ${_secp_pkg_cfg} _libsecpLines)
file(WRITE ${_secp_pkg_cfg} "")
foreach(line ${_libsecpLines})
    string(REGEX MATCH "^prefix=.*" out ${line})
    if (out)
        file(APPEND ${_secp_pkg_cfg} "prefix=${_absolute_prefix}\n")
    else()
        file(APPEND ${_secp_pkg_cfg} "${line}\n")
    endif()
endforeach()
