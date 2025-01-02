set(MODULE_NAME "utils")

add_library(${MODULE_NAME} STATIC)

target_include_directories(${MODULE_NAME}
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_sources(${MODULE_NAME}
    PRIVATE
        source/Printer.cpp
        source/Pipe.cpp
        source/benchmark/Benchmarker.cpp
        source/benchmark/BenchmarkResults.cpp
        source/benchmark/Timestamp.cpp
        source/Table.cpp
)
