cmake_minimum_required(VERSION 3.6)
project(client)

set(CMAKE_CXX_STANDARD 11)

add_definitions(-D_DEBUG)

set(COMMON_DIR ../common/)
#include_directories(${COMMON_DIR})

set(COMMON
        ${COMMON_DIR}/args.c
        ${COMMON_DIR}/common.c
        ${COMMON_DIR}/core.c
        ${COMMON_DIR}/lock.c
        ${COMMON_DIR}/command.c
        ${COMMON_DIR}/base_commands.c)

set(SOURCE_FILES main.c console.c)
add_executable(client ${SOURCE_FILES} ${COMMON})
target_link_libraries(client pthread)