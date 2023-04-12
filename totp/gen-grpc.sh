#!/usr/bin/env bash
protoc --grpc_out=./generated --cpp_out=./generated --plugin=protoc-gen-grpc=/usr/bin/grpc_cpp_plugin src/totp.proto
