add_executable(ecdh_textbook)

add_subdirectory(source)

target_link_libraries(ecdh_textbook PRIVATE utils)
target_include_directories(ecdh_textbook PRIVATE include)

