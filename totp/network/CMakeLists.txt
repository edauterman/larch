cmake_minimum_required(VERSION 2.8)

find_package(Threads REQUIRED)

set(CMAKE_C_FLAGS "-Wall -lpthread -lssl -lcrypto")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++14 -g")


if(GRPC_AS_SUBMODULE)  
add_subdirectory(../../.. ${CMAKE_CURRENT_BINARY_DIR}/grpc EXCLUDE_FROM_ALL)
 message(STATUS "Using gRPC via add_subdirectory.") 
set(_PROTOBUF_LIBPROTOBUF libprotobuf)
  set(_REFLECTION grpc++_reflection)
  if(CMAKE_CROSSCOMPILING)
    find_program(_PROTOBUF_PROTOC protoc)
  else()
    set(_PROTOBUF_PROTOC $<TARGET_FILE:protobuf::protoc>)
  endif()
  set(_GRPC_GRPCPP grpc++)
  if(CMAKE_CROSSCOMPILING)
    find_program(_GRPC_CPP_PLUGIN_EXECUTABLE grpc_cpp_plugin)
  else()
    set(_GRPC_CPP_PLUGIN_EXECUTABLE $<TARGET_FILE:grpc_cpp_plugin>)
  endif()
elseif(GRPC_FETCHCONTENT)
  # Another way is to use CMake's FetchContent module to clone gRPC at
  # configure time. This makes gRPC's source code available to your project,
  # similar to a git submodule.
  message(STATUS "Using gRPC via add_subdirectory (FetchContent).")
  include(FetchContent)
  FetchContent_Declare(
    grpc
    GIT_REPOSITORY https://github.com/grpc/grpc.git
    # when using gRPC, you will actually set this to an existing tag, such as
    # v1.25.0, v1.26.0 etc..
    # For the purpose of testing, we override the tag used to the commit
    # that's currently under test.
    GIT_TAG        vGRPC_TAG_VERSION_OF_YOUR_CHOICE)
  FetchContent_MakeAvailable(grpc)

  # Since FetchContent uses add_subdirectory under the hood, we can use
  # the grpc targets directly from this build.
  set(_PROTOBUF_LIBPROTOBUF libprotobuf)
  set(_REFLECTION grpc++_reflection)
  set(_PROTOBUF_PROTOC $<TARGET_FILE:protoc>)
  set(_GRPC_GRPCPP grpc++)
  if(CMAKE_CROSSCOMPILING)
    find_program(_GRPC_CPP_PLUGIN_EXECUTABLE grpc_cpp_plugin)
  else()
    set(_GRPC_CPP_PLUGIN_EXECUTABLE $<TARGET_FILE:grpc_cpp_plugin>)
  endif()
else()
  # This branch assumes that gRPC and all its dependencies are already installed
  # on this system, so they can be located by find_package().

  # Find Protobuf installation
  # Looks for protobuf-config.cmake file installed by Protobuf's cmake installation.
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
  if(CMAKE_CROSSCOMPILING)
    find_program(_GRPC_CPP_PLUGIN_EXECUTABLE grpc_cpp_plugin)
  else()
    set(_GRPC_CPP_PLUGIN_EXECUTABLE $<TARGET_FILE:gRPC::grpc_cpp_plugin>)
  endif()
endif()

# Proto file
get_filename_component(hw_proto "./totp.proto" ABSOLUTE)
get_filename_component(hw_proto_path "${hw_proto}" PATH)

# Generated sources
set(hw_proto_srcs "${CMAKE_CURRENT_BINARY_DIR}/totp.pb.cc")
set(hw_proto_hdrs "${CMAKE_CURRENT_BINARY_DIR}/totp.pb.h")
set(hw_grpc_srcs "${CMAKE_CURRENT_BINARY_DIR}/totp.grpc.pb.cc")
set(hw_grpc_hdrs "${CMAKE_CURRENT_BINARY_DIR}/totp.grpc.pb.h")
add_custom_command(
      OUTPUT "${hw_proto_srcs}" "${hw_proto_hdrs}" "${hw_grpc_srcs}" "${hw_grpc_hdrs}"
      COMMAND ${_PROTOBUF_PROTOC}
      ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}"
        --cpp_out "${CMAKE_CURRENT_BINARY_DIR}"
        -I "${hw_proto_path}"
        --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
        "${hw_proto}"
      DEPENDS "${hw_proto}")
add_custom_target(protos DEPENDS ${hw_proto_srcs} ${hw_proto_hdrs} ${hw_grpc_hdrs} ${hw_grpc_srcs})

add_library(log_proto
    ${hw_proto_srcs}
    ${hw_proto_hdrs}
    ${hw_grpc_srcs}
    ${hw_grpc_hdrs}
)

target_link_libraries(log_proto
    ${_REFLECTION}
    ${_GRPC_GRPCPP}
    ${_PROTOBUF_LIBPROTOBUF}
)

# Include generated *.pb.h files
include_directories("${CMAKE_CURRENT_BINARY_DIR}")
