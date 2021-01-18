# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

project(SEAL_proj VERSION 1.0)

add_executable(transpose transpose.cpp)
add_executable(multiplication_sq multiplication_sq.cpp)
add_executable(addition addition.cpp)
add_executable(subtraction subtraction.cpp)
add_executable(multiplication multiplication.cpp)
add_executable(determinant determinant.cpp)


find_package(SEAL 3.6.0 EXACT REQUIRED)

# set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
target_link_libraries(transpose SEAL::seal)
target_link_libraries(multiplication SEAL::seal)
target_link_libraries(addition SEAL::seal)
target_link_libraries(subtraction SEAL::seal)
target_link_libraries(multiplication_sq SEAL::seal)
target_link_libraries(determinant SEAL::seal)

