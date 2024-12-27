add_executable(textbook)

add_subdirectory(source)

target_link_libraries(textbook PRIVATE utils)
target_include_directories(textbook PRIVATE include)

