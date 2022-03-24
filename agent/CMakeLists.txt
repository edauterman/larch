cmake_minimum_required (VERSION 2.8.12)
project("ZKboo")

set (CMAKE_CXX_STANDARD 11)
set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/build)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include_directories(
    ${CMAKE_SOURCE_DIR}
    ${PROTOBUF_INCLUDE_DIRS}
    ${PROTO_GRPC_DIR})

message(STATUS "Finding Protobuf before gRPC")
include(FindProtobuf)
find_package(Protobuf REQUIRED)
find_package(OpenSSL REQUIRED)
# Find gRPC installation
# Looks for gRPCConfig.cmake file installed by gRPC's cmake installation.
find_package(gRPC CONFIG REQUIRED)
message(STATUS "Using gRPC ${gRPC_VERSION}")

set(protobuf_MODULE_COMPATIBLE TRUE)
message(STATUS "Using protobuf ${Protobuf_VERSION}")

set(_PROTOBUF_LIBPROTOBUF protobuf::libprotobuf)
set(_REFLECTION gRPC::grpc++_reflection)
if(CMAKE_CROSSCOMPILING)
    find_program(_PROTOBUF_PROTOC protoc)
else()
    set(_PROTOBUF_PROTOC $<TARGET_FILE:protobuf::protoc>)
endif()

include_directories(${OPENSSL_INCLUDE_DIR})
find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)
include(${CMAKE_FOLDER}/cmake/emp-base.cmake)
set(sources
    ../emp-tool/emp-tool/emp-tool.cpp
    ../emp-tool/emp-tool/circuits/files/bristol_fashion/Keccak_f.txt.cpp
    )   

set(_GRPC_GRPCPP gRPC::grpc++)

set(hw_proto_hdrs "${CMAKE_CURRENT_BINARY_DIR}/../network/log.pb.h")
set(hw_proto_srcs "${CMAKE_CURRENT_BINARY_DIR}/../network/log.pb.cc")
set(hw_grpc_hdrs "${CMAKE_CURRENT_BINARY_DIR}/../network/log.grpc.pb.h")
set(hw_grpc_srcs "${CMAKE_CURRENT_BINARY_DIR}/../network/log.grpc.pb.cc")

add_library(Utils asn1.cc base64.cc sig_parse.cc x509.cc params.cc client.cc ../zkboo/src/prover.cc ../zkboo/src/proof.cc ../zkboo/src/prover.cc ../zkboo/src/prover_sys.cc ../zkboo/src/view.cc ../zkboo/src/common.cc ../zkboo/src/verifier.cc ../zkboo/src/circuit.cc ../zkboo/src/circuit_utils.cc ${hw_proto_srcs} ${hw_grpc_srcs})

add_executable(agent agent.cc)
target_link_libraries(agent
    Prover
    Base
    Utils
    OpenSSL::SSL
    ${_REFLECTION}
    ${_GRPC_GRPCPP}
    ${_PROTOBUF_LIBPROTOBUF})
