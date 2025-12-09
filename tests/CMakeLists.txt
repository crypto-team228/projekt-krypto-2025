add_library(_tests
    test_aes.cpp
)
target_include_directories(_tests PUBLIC ${CMAKE_SOURCE_DIR}/include)

# Create test executable
add_executable(test_aes test_aes.cpp)
target_link_libraries(test_aes PRIVATE _src_AES)
target_include_directories(test_aes PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Register test with CTest
add_test(NAME AES_Tests COMMAND test_aes)
