cmake_minimum_required (VERSION 2.8.12)
project("ZKboo")
add_compile_options(-DTHREADING)
set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/build)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include_directories(
	${CMAKE_SOURCE_DIR})

find_package(OpenSSL REQUIRED)
find_package(emp-tool REQUIRED)

include_directories(${EMP-TOOL_INCLUDE_DIRS})
include_directories(${OPENSSL_INCLUDE_DIR})
#include(emp-base.cmake)

find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)
include(${CMAKE_FOLDER}/cmake/emp-base.cmake)
set(sources
    ../../emp-tool/emp-tool/emp-tool.cpp
    ../../emp-tool/emp-tool/circuits/files/bristol_fashion/Keccak_f.txt.cpp
    ../../emp-tool/emp-tool/circuits/files/bristol_fashion/aes_128.txt.cpp
    )
add_library(Base SHARED ${sources})

add_subdirectory(src)
add_subdirectory(test)
