set(MODULE_NAME industy_standard)

add_executable(${MODULE_NAME} 
    source/main.cpp
    source/SecurityLevel.cpp
)

target_include_directories(${MODULE_NAME} PRIVATE include)
target_link_libraries(${MODULE_NAME} PRIVATE crypto utils)
