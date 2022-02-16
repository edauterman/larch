cmake_minimum_required (VERSION 2.8.12)
project("ZKboo")

set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/build)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include_directories(
	${CMAKE_SOURCE_DIR})

find_package(OpenSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})

find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)
include(${CMAKE_FOLDER}/cmake/emp-base.cmake)

add_subdirectory(zkboo)
