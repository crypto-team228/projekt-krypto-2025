add_library(src_cli
    cli.cpp
)
target_include_directories(src_cli PUBLIC ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/external)
