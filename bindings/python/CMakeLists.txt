if(CMAKE_CROSSCOMPILING)
    message(FATAL_ERROR "Cross compiling python wheel is not supported")
endif()

find_package(Python3 COMPONENTS Development.Module REQUIRED)
if(NOT Python3_Development.Module_FOUND)
    message(FATAL_ERROR "Python3:: Development.Module not found")
endif()

find_package(SWIG REQUIRED)
include(UseSWIG)

set_source_files_properties(swig.i PROPERTIES
    CPLUSPLUS OFF
    SWIG_MODULE_NAME "bindings"
    USE_SWIG_DEPENDENCIES TRUE
    INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/src"
    GENERATED_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR};${CMAKE_SOURCE_DIR}/src"
)
swig_add_library(swig_bindings
    TYPE MODULE
    LANGUAGE python
    SOURCES swig.i
)
target_link_libraries(swig_bindings PRIVATE wallycore Python3::Module)
target_compile_definitions(swig_bindings PUBLIC SWIG_PYTHON)

install(TARGETS swig_bindings
    COMPONENT bindings
    LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_PREFIX}
    RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}
)
get_property(_wrapper_py_file TARGET swig_bindings PROPERTY SWIG_SUPPORT_FILES)
install(
    FILES ${_wrapper_py_file}
    COMPONENT bindings
    DESTINATION ${CMAKE_INSTALL_PREFIX}
)
