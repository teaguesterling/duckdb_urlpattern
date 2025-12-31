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
