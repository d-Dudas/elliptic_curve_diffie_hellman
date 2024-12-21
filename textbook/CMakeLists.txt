cmake_minimum_required(VERSION 3.10)

project(EllipticCurveDiffieHellman_Textbook)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror -Wpedantic -O0 -g")

add_executable(ecdh_textbook)

add_subdirectory(source)

target_include_directories(ecdh_textbook PRIVATE
    include
)

