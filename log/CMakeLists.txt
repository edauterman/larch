include_directories(
	${CMAKE_SOURCE_DIR}
	${PROTOBUF_INCLUDE_DIRS}
	${PROTO_GRPC_DIR})

message(STATUS "Finding Protobuf before gRPC")
include(FindProtobuf)
find_package(Protobuf REQUIRED)
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

set(_GRPC_GRPCPP gRPC::grpc++)

set(hw_proto_hdrs "${CMAKE_CURRENT_BINARY_DIR}/../network/log.pb.h")
set(hw_proto_srcs "${CMAKE_CURRENT_BINARY_DIR}/../network/log.pb.cc")
set(hw_grpc_hdrs "${CMAKE_CURRENT_BINARY_DIR}/../network/log.grpc.pb.h")
set(hw_grpc_srcs "${CMAKE_CURRENT_BINARY_DIR}/../network/log.grpc.pb.cc")

add_executable(log log.cc ${hw_proto_srcs} ${hw_grpc_srcs})

target_link_libraries(log
	${_REFLECTION}
	${_GRPC_GRPCPP}
	${_PROTOBUF_LIBPROTOBUF})
