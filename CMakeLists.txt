cmake_minimum_required (VERSION 2.6)
project (SctpCat)
set (SctpCat_VERSION_MAJOR 1)
set (SctpCat_VERSION_MINOR 1)

configure_file (
    "${PROJECT_SOURCE_DIR}/sctpcat_config.h.in"
    "${PROJECT_BINARY_DIR}/sctpcat_config.h"
)
include_directories ("${PROJECT_BINARY_DIR}")
add_definitions("-DHAVE_SCTPCAT_CONFIG_H")

set (SctpCat_SOURCES
    addrinfo.cpp
    consolethread.cpp
    pingthread.cpp
    sctpcat.cpp
    util.cpp
)

add_executable (sctpcat ${SctpCat_SOURCES})

target_link_libraries(sctpcat boost_program_options boost_thread)
target_link_libraries(sctpcat sctp)
