cmake_minimum_required (VERSION 2.8.12)
project("ZKboo")

set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/build)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include_directories(
	${CMAKE_SOURCE_DIR})

find_package(OpenSSL REQUIRED)
find_package(emp-tool REQUIRED)
#find_package(OpenMP REQUIRED)

#set(OpenMP_CXX "${CMAKE_CXX_COMPILER}")
#set(OpenMP_CXX_FLAGS "-fopenmp=libomp -Wno-unused-command-line-argument")
#set(OpenMP_CXX_LIB_NAMES "libomp" "libgomp" "libiomp5")
#set(OpenMP_libomp_LIBRARY ${OpenMP_CXX_LIB_NAMES})
#set(OpenMP_libgomp_LIBRARY ${OpenMP_CXX_LIB_NAMES})
#set(OpenMP_libiomp5_LIBRARY ${OpenMP_CXX_LIB_NAMES})

#set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")

include_directories(${EMP-TOOL_INCLUDE_DIRS})
include_directories(${OPENSSL_INCLUDE_DIR})
#include(emp-base.cmake)

find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)
include(${CMAKE_FOLDER}/cmake/emp-base.cmake)
set(sources
    /home/ec2-user/emp-tool/emp-tool/emp-tool.cpp
    /home/ec2-user/emp-tool/emp-tool/circuits/files/bristol_fashion/Keccak_f.txt.cpp
    )

add_executable(prover_test prover_test.cc)
target_link_libraries(prover_test
	Prover
    Base
    OpenSSL::SSL)

add_executable(hash_test hash_test.cc)
target_link_libraries(hash_test
	Prover
    Base
    OpenSSL::SSL)

add_executable(ct_test ct_test.cc)
target_link_libraries(ct_test
	Prover
    Base
    OpenSSL::SSL)
#OpenMP::OpenMP_CXX)

add_executable(serialize_test serialize_test.cc)
target_link_libraries(serialize_test
	Prover
    Base
    OpenSSL::SSL)

add_executable(parallel_test parallel_test.cc)
target_link_libraries(parallel_test
	Prover
    Base
    OpenSSL::SSL)
