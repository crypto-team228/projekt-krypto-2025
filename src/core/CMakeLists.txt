add_library(src_core
    SecretKey.cpp
)
target_include_directories(src_core PUBLIC ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/external)
