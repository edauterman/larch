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
    ../../../emp-tool/emp-tool/emp-tool.cpp
    ../../../emp-tool/emp-tool/circuits/files/bristol_fashion/Keccak_f.txt.cpp
    )   

add_executable(or_test or_test.cc ../src/or_groth.cc ../src/params.cc)
target_link_libraries(or_test
    OpenSSL::SSL)

add_executable(pw_test pw_test.cc ../src/pw.cc ../src/or_groth.cc ../src/params.cc ../src/sigs.cc)
target_link_libraries(pw_test
    OpenSSL::SSL)

add_executable(sigs_test sigs_test.cc ../src/sigs.cc ../src/params.cc)
target_link_libraries(sigs_test
    OpenSSL::SSL)
