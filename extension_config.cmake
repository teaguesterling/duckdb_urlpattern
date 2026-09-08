# This file is included by DuckDB's build system. It specifies which extension to load

# Extension from this repo
#
# WASM: the emcc -sSIDE_MODULE link that produces the loadable .wasm embeds ONLY the
# libraries named in DUCKDB_EXTENSION_URLPATTERN_LINKED_LIBS -- it ignores
# target_link_libraries() -- so without LINKED_LIBS the .wasm builds green with
# unresolved ada imports that throw on first call (issue #4). See the long comment in
# CMakeLists.txt for the mechanism.
#
# The $<TARGET_FILE:ada::ada> generator expression is safe here even though this file
# is include()d in duckdb's directory scope, because a genexpr is a plain string until
# it is USED: duckdb_extension_load only propagates it, and the only consumer is the
# add_custom_command created by build_loadable_extension() -- which is called from
# THIS repo's CMakeLists.txt, after find_package(ada CONFIG REQUIRED) has created the
# imported target in that same directory scope. Verified by probing the resolved value
# at that exact point in a real DuckDB configure, both with CMAKE_BUILD_TYPE=Release
# and with it unset (duckdb defaults it to Release, which is what the wasm targets get
# since they pass no build type): both resolve to the release libada.a.
#
# And if ada::ada were ever NOT visible there, $<TARGET_FILE:...> is a hard CMake
# generate-time error ("No target ada::ada"), not an empty expansion -- so this cannot
# silently degrade back into the unresolved-imports bug it fixes.
duckdb_extension_load(urlpattern
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}
    LOAD_TESTS
    LINKED_LIBS "$<TARGET_FILE:ada::ada>"
)

# Any extra extensions that should be built
# e.g.: duckdb_extension_load(json)
