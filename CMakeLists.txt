cmake_minimum_required(VERSION 3.10)

project(EllipticCurveDiffieHellman)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror -Wpedantic -O0 -g")

add_subdirectory(utils)
add_subdirectory(textbook)
add_subdirectory(industry_standard)
