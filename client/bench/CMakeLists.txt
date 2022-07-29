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
    ../../emp-tool/emp-tool/emp-tool.cpp
    ../../emp-tool/emp-tool/circuits/files/bristol_fashion/Keccak_f.txt.cpp
    )   

set(_GRPC_GRPCPP gRPC::grpc++)

set(hw_proto_hdrs "${CMAKE_CURRENT_BINARY_DIR}/../../network/log.pb.h")
set(hw_proto_srcs "${CMAKE_CURRENT_BINARY_DIR}/../../network/log.pb.cc")
set(hw_grpc_hdrs "${CMAKE_CURRENT_BINARY_DIR}/../../network/log.grpc.pb.h")
set(hw_grpc_srcs "${CMAKE_CURRENT_BINARY_DIR}/../../network/log.grpc.pb.cc")

add_executable(agent agent.cc)
target_link_libraries(agent
    Client
    Prover
    Base
    OpenSSL::SSL
    ${_REFLECTION}
    ${_GRPC_GRPCPP}
    ${_PROTOBUF_LIBPROTOBUF})

add_executable(init init.cc)
target_link_libraries(init
    Client
    Prover
    Base
    OpenSSL::SSL
    ${_REFLECTION}
    ${_GRPC_GRPCPP}
    ${_PROTOBUF_LIBPROTOBUF})

add_executable(init_reg_auth init_reg_auth.cc)
target_link_libraries(init_reg_auth
    Client
    Prover
    Base
    OpenSSL::SSL
    ${_REFLECTION}
    ${_GRPC_GRPCPP}
    ${_PROTOBUF_LIBPROTOBUF})

add_executable(convert_circuit convert_circuit.cc)
target_link_libraries(convert_circuit
    Client
    Prover
    Base
    OpenSSL::SSL
    ${_REFLECTION}
    ${_GRPC_GRPCPP}
    ${_PROTOBUF_LIBPROTOBUF})

add_executable(sigs_bench sigs_bench.cc)
target_link_libraries(sigs_bench
    Client
    Prover
    Base
    OpenSSL::SSL
    ${_REFLECTION}
    ${_GRPC_GRPCPP}
    ${_PROTOBUF_LIBPROTOBUF})

add_executable(auth_bench auth_bench.cc)
target_link_libraries(auth_bench
    Client
    Prover
    Base
    OpenSSL::SSL
    ${_REFLECTION}
    ${_GRPC_GRPCPP}
    ${_PROTOBUF_LIBPROTOBUF})

add_executable(throughput_bench throughput_bench.cc)
target_link_libraries(throughput_bench
    Client
    Prover
    Base
    OpenSSL::SSL
    ${_REFLECTION}
    ${_GRPC_GRPCPP}
    ${_PROTOBUF_LIBPROTOBUF})

add_executable(baseline_bench baseline_bench.cc)
target_link_libraries(baseline_bench
    Client
    Prover
    Base
    OpenSSL::SSL
    ${_REFLECTION}
    ${_GRPC_GRPCPP}
    ${_PROTOBUF_LIBPROTOBUF})
