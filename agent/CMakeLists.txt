cmake_minimum_required (VERSION 2.8.12)
project("ZKboo")

set (CMAKE_CXX_STANDARD 11)
set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/build)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include_directories(
	${CMAKE_SOURCE_DIR})

find_package(OpenSSL REQUIRED)
#find_package(emp-tool REQUIRED)

#include_directories(${EMP-TOOL_INCLUDE_DIRS})
include_directories(${OPENSSL_INCLUDE_DIR})
#include(emp-base.cmake)

find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)
include(${CMAKE_FOLDER}/cmake/emp-base.cmake)
set(sources
    ../emp-tool/emp-tool/emp-tool.cpp
    ../emp-tool/emp-tool/circuits/files/bristol_fashion/Keccak_f.txt.cpp
    )

add_library(Utils asn1.cc base64.cc sig_parse.cc x509.cc params.cc client.cc ../zkboo/src/prover.cc ../zkboo/src/proof.cc ../zkboo/src/prover.cc ../zkboo/src/prover_sys.cc ../zkboo/src/view.cc ../zkboo/src/common.cc ../zkboo/src/verifier.cc ../zkboo/src/circuit.cc ../zkboo/src/circuit_utils.cc)

add_executable(agent agent.cc)
target_link_libraries(agent
    Prover
    Base
    Utils
    OpenSSL::SSL)
