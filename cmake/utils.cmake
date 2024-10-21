include(CheckCCompilerFlag)
include(CheckIncludeFile)
include(CheckFunctionExists)
include(CheckCSourceRuns)

function(generate_config_file)
    check_function_exists("explicit_bzero" HAVE_EXPLICIT_BZERO)
    check_function_exists("explicit_memset" HAVE_EXPLICIT_MEMSET)
    check_c_source_compiles(
        "int main(void) {int a = 42; int *pnt = &a; __asm__ __volatile__ (\"\" : : \"r\"(pnt) : \"memory\");}"
        HAVE_INLINE_ASM
    )
    check_include_file("mbedtls/sha512.h" HAVE_MBEDTLS_SHA512_H)
    check_function_exists("mmap" HAVE_MMAP)
    check_function_exists("posix_memalign" HAVE_POSIX_MEMALIGN)
    check_include_file("sys/mman.h" HAVE_SYS_MMAN_H)
    if(CMAKE_CROSSCOMPILING)
        unset(HAVE_UNALIGNED_ACCESS)
    else()
        check_c_source_runs(
            "int main(void){static int a[2];return *((int*)(((char*)a)+1)) != 0;}" HAVE_UNALIGNED_ACCESS
        )
    endif()
    set(PACKAGE \"${CMAKE_PROJECT_NAME}\")
    set(PACKAGE_BUGREPORT \"\")
    set(PACKAGE_NAME \"${CMAKE_PROJECT_NAME}\")
    set(PACKAGE_STRING "\"${CMAKE_PROJECT_NAME} ${CMAKE_PROJECT_VERSION}\"")
    set(PACKAGE_TARNAME \"${CMAKE_PROJECT_NAME}\")
    set(PACKAGE_URL \"${CMAKE_PROJECT_URL}\")
    set(PACKAGE_VERSION \"${CMAKE_PROJECT_VERSION}\")
    set(VERSION \"${CMAKE_PROJECT_VERSION}\")

    configure_file(cmake/config.h.in config.h)
endfunction()
