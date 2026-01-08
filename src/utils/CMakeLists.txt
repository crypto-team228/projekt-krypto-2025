add_library(src_utils
    cipherFactory.cpp
    modeFactory.cpp
 )
target_include_directories(src_utils PUBLIC ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/external)
