cmake_minimum_required (VERSION 2.8.12)
project("ZKboo")

set (CMAKE_CXX_STANDARD 11)
set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/build)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include_directories(
    ${CMAKE_SOURCE_DIR})

find_package(OpenSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})
find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)
include(${CMAKE_FOLDER}/cmake/emp-base.cmake)
set(sources
    ../../emp-tool/emp-tool/emp-tool.cpp
    ../../emp-tool/emp-tool/circuits/files/bristol_fashion/Keccak_f.txt.cpp
    )   

add_executable(ddh_test ddh_test.cc ../src/ddh_proof.cc ../src/params.cc)
target_link_libraries(ddh_test
    OpenSSL::SSL)
