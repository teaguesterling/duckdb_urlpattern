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

# WASM SIDE-MODULE LINKING (issue #4).
#
# The loadable .wasm is NOT produced by the CMake link step below. It comes from a
# separate emcc invocation in duckdb/extension/extension_build_tools.cmake
# (build_loadable_extension_base, the if(EMSCRIPTEN) block):
#
#   set(TO_BE_LINKED ${DUCKDB_EXTENSION_<NAME>_LINKED_LIBS})
#   emcc <archive> -o <out>.wasm -O3 -sSIDE_MODULE=2 ... ${TO_BE_LINKED}
#
# TO_BE_LINKED comes from that variable and NOTHING else, so the
# target_link_libraries() calls below are honoured for the native build and IGNORED
# by the wasm link. Any library not named there is left as an unresolved import: the
# .wasm builds, CI goes green because building never instantiates the module, and the
# first urlpattern call throws in the user's browser. Known failure class in this
# family of extensions -- duckdb_markdown#19, duckdb_webbed#96, duckdb_yaml#40.
#
# ada is therefore named via LINKED_LIBS in extension_config.cmake; see the comment
# there for why the generator expression is safe.
#
# WASM is currently excluded from the CI matrix (emscripten clang still SIGSEGVs on
# ada-url's C++20 templates), so that link is not exercised today.

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
