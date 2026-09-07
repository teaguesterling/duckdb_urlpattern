cmake_minimum_required(VERSION 3.5)

# Set extension name here
set(TARGET_NAME urlpattern)

# Find Ada URL library via vcpkg
find_package(ada CONFIG REQUIRED)

set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})
include_directories(src/include)

set(EXTENSION_SOURCES
    src/urlpattern_extension.cpp
)

# WASM SIDE-MODULE LINKING. The loadable .wasm is not produced by the normal CMake
# link step. It comes from a SEPARATE emcc invocation
# (duckdb/extension/extension_build_tools.cmake, the EMSCRIPTEN block in
# build_loadable_extension):
#
#   emcc <archive> -o <out>.wasm -O3 -sSIDE_MODULE=2 ... ${TO_BE_LINKED}
#
# where TO_BE_LINKED comes from DUCKDB_EXTENSION_URLPATTERN_LINKED_LIBS and NOTHING
# else. The target_link_libraries() calls below are honoured for the native build and
# IGNORED by that link. Any library not named here is left as an unresolved import:
# the .wasm builds, CI goes green because building never instantiates the module, and
# the first urlpattern call throws in the user's browser.
#
# This is a known, repeatedly-shipped failure class in this family of extensions --
# duckdb_markdown#19, duckdb_webbed#96, duckdb_yaml#40 -- and this repo's instance of
# it is issue #4.
#
# WASM is currently excluded from the CI matrix (emscripten clang still SIGSEGVs on
# ada-url's C++20 templates), so this block is not exercised today. It is here so that
# lifting that exclude does not immediately re-ship a .wasm that fails at LOAD.
#
# Resolved HERE rather than as a $<TARGET_FILE:ada::ada> genexpr in
# extension_config.cmake: that file is evaluated in duckdb's directory scope, where
# this find_package() imported target need not be visible, and an unresolvable
# genexpr expands to the EMPTY STRING rather than erroring -- precisely the silent
# success this block exists to prevent.
#
# Must precede build_loadable_extension(), which reads the variable at call time.
if(WASM_LOADABLE_EXTENSIONS)
    # ada::ada is a STATIC IMPORTED target (vcpkg ada-url) carrying a real archive on
    # IMPORTED_LOCATION_<CONFIG>, and it declares no INTERFACE_LINK_LIBRARIES, so the
    # single libada.a is the whole dependency. Read the location directly: the
    # per-config property is not guaranteed to match CMAKE_BUILD_TYPE, so try the
    # active config, then the configs ada actually shipped, then the unsuffixed one.
    set(_urlpattern_ada_lib "")
    if(TARGET ada::ada)
        if(CMAKE_BUILD_TYPE)
            string(TOUPPER "${CMAKE_BUILD_TYPE}" _urlpattern_cfg)
            get_target_property(_urlpattern_ada_lib ada::ada IMPORTED_LOCATION_${_urlpattern_cfg})
        endif()
        if(NOT _urlpattern_ada_lib)
            # RELEASE first: vcpkg ships both, IMPORTED_CONFIGURATIONS happens to list
            # DEBUG first, and a debug libada.a links just as successfully while making
            # the .wasm substantially larger. Only fall through to whatever else exists.
            get_target_property(_urlpattern_ada_cfgs ada::ada IMPORTED_CONFIGURATIONS)
            if(_urlpattern_ada_cfgs)
                list(REMOVE_ITEM _urlpattern_ada_cfgs RELEASE)
                list(INSERT _urlpattern_ada_cfgs 0 RELEASE)
                foreach(_urlpattern_cfg IN LISTS _urlpattern_ada_cfgs)
                    get_target_property(_urlpattern_ada_lib ada::ada IMPORTED_LOCATION_${_urlpattern_cfg})
                    if(_urlpattern_ada_lib)
                        break()
                    endif()
                endforeach()
            endif()
        endif()
        if(NOT _urlpattern_ada_lib)
            get_target_property(_urlpattern_ada_lib ada::ada IMPORTED_LOCATION)
        endif()
    endif()

    if(_urlpattern_ada_lib)
        set(DUCKDB_EXTENSION_URLPATTERN_LINKED_LIBS "${_urlpattern_ada_lib}")
        # Printed so the CI log shows WHICH archive was linked -- a debug archive
        # resolves every symbol just as well as a release one, so a downstream symbol
        # check cannot tell them apart. This line is the only place that can.
        message(STATUS "urlpattern WASM link libs: ${DUCKDB_EXTENSION_URLPATTERN_LINKED_LIBS}")
    else()
        # Fail the BUILD rather than emit a .wasm that loads and then throws.
        message(FATAL_ERROR
            "urlpattern: could not resolve the ada::ada archive path for the WASM link. "
            "Without it the -sSIDE_MODULE=2 link silently leaves ada symbols unresolved "
            "and the extension fails at LOAD. See issue #4.")
    endif()
endif()

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

# Link Ada URL library
target_link_libraries(${EXTENSION_NAME} ada::ada)
target_link_libraries(${LOADABLE_EXTENSION_NAME} ada::ada)

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
