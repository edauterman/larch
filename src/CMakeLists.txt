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

add_library(Prover prover.cc emp_prover.cc view.cc common.cc verifier.cc)

add_executable(prover_test prover_test.cc)
target_link_libraries(prover_test
	Prover
	OpenSSL::SSL)
