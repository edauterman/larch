cmake_minimum_required (VERSION 2.8.12)
project("ZKboo")

set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/build)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include_directories(
	${CMAKE_SOURCE_DIR})

find_package(OpenSSL REQUIRED)
find_package(emp-tool REQUIRED)

set(CMAKE_C_FLAGS "-Wall -pthread")
#set(CMAKE_C_FLAGS "-Wall -lpthread -lssl -lcrypto")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++14 -g")

include_directories(${EMP-TOOL_INCLUDE_DIRS})
include_directories(${OPENSSL_INCLUDE_DIR})
set(sources
    /home/ec2-user/emp-tool/emp-tool/emp-tool.cpp)

find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)
include(${CMAKE_FOLDER}/cmake/emp-base.cmake)

add_subdirectory(zkboo)
#add_subdirectory(network)
#add_subdirectory(agent)
#add_subdirectory(log)
