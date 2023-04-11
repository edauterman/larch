cmake_minimum_required(VERSION 2.8.11)
project(larch-totp)
set(NAME "larch-totp")

find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)
include(${CMAKE_FOLDER}/cmake/emp-base.cmake)

include_directories(
    ${CMAKE_SOURCE_DIR}
    ${PROTOBUF_INCLUDE_DIRS}
    ${PROTO_GRPC_DIR})

message(STATUS "Finding Protobuf before gRPC")
include(FindProtobuf)
find_package(Protobuf REQUIRED)
find_package(emp-tool REQUIRED)
include_directories(${EMP-TOOL_INCLUDE_DIRS})
find_package(emp-ot REQUIRED)
find_package(emp-ag2pc REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(gRPC REQUIRED)

include_directories(${EMP-TOOL_INCLUDE_DIRS})
include_directories(${OPENSSL_INCLUDE_DIR})
set(sources
    /home/ec2-user/emp-tool/emp-tool/emp-tool.cpp)
find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)
include(${CMAKE_FOLDER}/cmake/emp-base.cmake)


add_compile_options(-Wno-deprecated-declarations -Wno-unused-function -Wno-unused-variable)
include_directories(generated)

# add_compile_options(-Og -g -fsanitize=address -fsanitize=undefined)
# add_link_options(-g -fsanitize=address -fsanitize=undefined)


# add_executable(gen-circuit circuitgen/gen-circuit.cpp ../../emp-tool-host/emp-tool/emp-tool.cpp ../../emp-tool-host/emp-tool/circuits/files/bristol_fashion/aes_128.cpp)
# target_compile_options(gen-circuit PRIVATE -DMAX_KEYS=64)

#add_executable(preparse circuitgen/preparse.cpp ../../emp-tool-host/emp-tool/emp-tool.cpp)


add_executable(client20-init src/client-init.cpp src/common.cpp generated/src/totp.grpc.pb.cc generated/src/totp.pb.cc src/base32.c src/sigs.cpp src/params.cpp)
target_link_libraries(client20-init PRIVATE OpenSSL::SSL OpenSSL::Crypto gRPC::grpc++)
target_compile_options(client20-init PRIVATE -DMAX_KEYS=20)

add_executable(client20-auth src/client-auth.cpp src/common.cpp generated/src/totp.grpc.pb.cc generated/src/totp.pb.cc src/base32.c src/sigs.cpp src/params.cpp)
target_link_libraries(client20-auth PRIVATE OpenSSL::SSL OpenSSL::Crypto gRPC::grpc++)
target_compile_options(client20-auth PRIVATE -DMAX_KEYS=20)

add_executable(server20 src/server.cpp src/common.cpp generated/src/totp.grpc.pb.cc generated/src/totp.pb.cc src/sigs.cpp src/params.cpp)
target_link_libraries(server20 PRIVATE OpenSSL::SSL OpenSSL::Crypto gRPC::grpc++)
target_compile_options(server20 PRIVATE -DMAX_KEYS=20)


#add_executable(client40-init src/client-init.cpp src/common.cpp generated/src/totp.grpc.pb.cc generated/src/totp.pb.cc src/base32.c src/sigs.cpp src/params.cpp)
#target_link_libraries(client40-init PRIVATE OpenSSL::SSL OpenSSL::Crypto gRPC::grpc++)
#target_compile_options(client40-init PRIVATE -DMAX_KEYS=40)

#add_executable(client40-auth src/client-auth.cpp src/common.cpp generated/src/totp.grpc.pb.cc generated/src/totp.pb.cc src/base32.c src/sigs.cpp src/params.cpp)
#target_link_libraries(client40-auth PRIVATE OpenSSL::SSL OpenSSL::Crypto gRPC::grpc++)
#target_compile_options(client40-auth PRIVATE -DMAX_KEYS=40)

#add_executable(server40 src/server.cpp src/common.cpp generated/src/totp.grpc.pb.cc generated/src/totp.pb.cc src/sigs.cpp src/params.cpp)
#target_link_libraries(server40 PRIVATE OpenSSL::SSL OpenSSL::Crypto gRPC::grpc++)
#target_compile_options(server40 PRIVATE -DMAX_KEYS=40)


#add_executable(client60-init src/client-init.cpp src/common.cpp generated/src/totp.grpc.pb.cc generated/src/totp.pb.cc src/base32.c src/sigs.cpp src/params.cpp)
#target_link_libraries(client60-init PRIVATE OpenSSL::SSL OpenSSL::Crypto gRPC::grpc++)
#target_compile_options(client60-init PRIVATE -DMAX_KEYS=60)

#add_executable(client60-auth src/client-auth.cpp src/common.cpp generated/src/totp.grpc.pb.cc generated/src/totp.pb.cc src/base32.c src/sigs.cpp src/params.cpp)
#target_link_libraries(client60-auth PRIVATE OpenSSL::SSL OpenSSL::Crypto gRPC::grpc++)
#target_compile_options(client60-auth PRIVATE -DMAX_KEYS=60)

#add_executable(server60 src/server.cpp src/common.cpp generated/src/totp.grpc.pb.cc generated/src/totp.pb.cc src/sigs.cpp src/params.cpp)
#target_link_libraries(server60 PRIVATE OpenSSL::SSL OpenSSL::Crypto gRPC::grpc++)
#target_compile_options(server60 PRIVATE -DMAX_KEYS=60)


#add_executable(client80-init src/client-init.cpp src/common.cpp generated/src/totp.grpc.pb.cc generated/src/totp.pb.cc src/base32.c src/sigs.cpp src/params.cpp)
#target_link_libraries(client80-init PRIVATE OpenSSL::SSL OpenSSL::Crypto gRPC::grpc++)
#target_compile_options(client80-init PRIVATE -DMAX_KEYS=80)

#add_executable(client80-auth src/client-auth.cpp src/common.cpp generated/src/totp.grpc.pb.cc generated/src/totp.pb.cc src/base32.c src/sigs.cpp src/params.cpp)
#target_link_libraries(client80-auth PRIVATE OpenSSL::SSL OpenSSL::Crypto gRPC::grpc++)
#target_compile_options(client80-auth PRIVATE -DMAX_KEYS=80)

#add_executable(server80 src/server.cpp src/common.cpp generated/src/totp.grpc.pb.cc generated/src/totp.pb.cc src/sigs.cpp src/params.cpp)
#target_link_libraries(server80 PRIVATE OpenSSL::SSL OpenSSL::Crypto gRPC::grpc++)
#target_compile_options(server80 PRIVATE -DMAX_KEYS=80)


#add_executable(client100-init src/client-init.cpp src/common.cpp generated/src/totp.grpc.pb.cc generated/src/totp.pb.cc src/base32.c src/sigs.cpp src/params.cpp)
#target_link_libraries(client100-init PRIVATE OpenSSL::SSL OpenSSL::Crypto gRPC::grpc++)
#target_compile_options(client100-init PRIVATE -DMAX_KEYS=100)

#add_executable(client100-auth src/client-auth.cpp src/common.cpp generated/src/totp.grpc.pb.cc generated/src/totp.pb.cc src/base32.c src/sigs.cpp src/params.cpp)
#target_link_libraries(client100-auth PRIVATE OpenSSL::SSL OpenSSL::Crypto gRPC::grpc++)
#target_compile_options(client100-auth PRIVATE -DMAX_KEYS=100)

#add_executable(server100 src/server.cpp src/common.cpp generated/src/totp.grpc.pb.cc generated/src/totp.pb.cc src/sigs.cpp src/params.cpp)
#target_link_libraries(server100 PRIVATE OpenSSL::SSL OpenSSL::Crypto gRPC::grpc++)
#target_compile_options(server100 PRIVATE -DMAX_KEYS=100)
