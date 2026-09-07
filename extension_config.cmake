# This file is included by DuckDB's build system. It specifies which extension to load

# Extension from this repo
#
# WASM: the emcc -sSIDE_MODULE link embeds ONLY the libraries named in
# DUCKDB_EXTENSION_URLPATTERN_LINKED_LIBS -- it ignores target_link_libraries() -- so a
# .wasm can build green with unresolved ada imports that throw on first call (issue #4).
#
# That variable is deliberately NOT set here as a LINKED_LIBS "$<TARGET_FILE:ada::ada>"
# genexpr: this file is evaluated in duckdb's directory scope, where the ada::ada
# imported target need not be visible, and an unresolvable genexpr expands to the empty
# string instead of erroring. It is set instead by CMakeLists.txt, where find_package(ada)
# has actually run and the archive path can be checked and reported; see the long comment
# there.
duckdb_extension_load(urlpattern
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}
    LOAD_TESTS
)

# Any extra extensions that should be built
# e.g.: duckdb_extension_load(json)
