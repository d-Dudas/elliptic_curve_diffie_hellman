set(EXECUTABLE ecdh_textbook)
set(SOURCES 
    main.cpp
    Printer.cpp
    Math.cpp
    KeyManager.cpp
    Pipe.cpp
)

list(TRANSFORM SOURCES PREPEND "${CMAKE_CURRENT_SOURCE_DIR}/")

target_sources(${EXECUTABLE} PRIVATE ${SOURCES})
