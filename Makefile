PROJ_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Configuration of extension
EXT_NAME=urlpattern
EXT_CONFIG=${PROJ_DIR}extension_config.cmake

# The Ada URL dependency exports cxx_std_20 as an INTERFACE compile feature, which
# propagates to every target that links the extension (duckdb_static, plan_serializer,
# shell, ...) and bumps them to c++20 -- while DuckDB's own core OBJECT libraries stay
# at their default c++11. That standard split turns BufferedFileWriter::DEFAULT_OPEN_FLAGS
# into a strong symbol in the c++11 archive but an inline (mergeable) variable in the
# c++20 consumers, producing a "multiple definition" link error (e.g. plan_serializer).
# Pin the whole build to a single standard >= c++17 so the member is an inline variable
# everywhere and the linker merges the definitions. DuckDB sets CMAKE_CXX_STANDARD via a
# non-FORCE cache entry, so this command-line -D wins.
EXT_FLAGS=-DCMAKE_CXX_STANDARD=17

# Include the Makefile from extension-ci-tools
include extension-ci-tools/makefiles/duckdb_extension.Makefile