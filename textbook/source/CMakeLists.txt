set(EXECUTABLE textbook)

set(SOURCES 
    Math.cpp
    main.cpp
    KeyManager.cpp
)

list(TRANSFORM SOURCES PREPEND "${CMAKE_CURRENT_SOURCE_DIR}/")

target_sources(${EXECUTABLE} PRIVATE ${SOURCES})
