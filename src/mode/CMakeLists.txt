add_library(src_mode
    CBC.cpp
    CTR.cpp
    ECB.cpp
)
target_include_directories(src_mode PUBLIC ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/external)
