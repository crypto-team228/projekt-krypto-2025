add_library(tests
    test_aes.cpp
    test_main.cpp
)
target_include_directories(_tests PUBLIC ${CMAKE_SOURCE_DIR}/include)
