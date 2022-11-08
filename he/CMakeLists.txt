# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.13)

include(/home/ec2-user/vcpkg/scripts/buildsystems/vcpkg.cmake)
find_package(SEAL CONFIG REQUIRED)

add_executable(sealexamples passwords.cpp)

target_link_libraries(sealexamples PRIVATE SEAL::seal)
