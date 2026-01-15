cmake_minimum_required(VERSION 3.15)
project(project-krypto)

include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)
FetchContent_MakeAvailable(googletest)

enable_testing()
include(GoogleTest)

add_subdirectory("src/cipher/AES")
add_subdirectory("src/cipher/TDES")
add_subdirectory("src/core")
add_subdirectory("src/mode")
add_subdirectory("src/utils")

add_executable(crypto_app_cli src/cli/cli.cpp)
target_link_libraries(crypto_app_cli PRIVATE src_cipher_AES src_cipher_TDES src_core src_mode src_utils)

add_executable(AES_app src/AES_main.cpp)
target_link_libraries(AES_app PRIVATE src_cipher_AES src_cipher_TDES src_core src_mode src_utils)

add_executable(TDES_app src/TDES_main.cpp)
target_link_libraries(TDES_app PRIVATE src_cipher_AES src_cipher_TDES src_core src_mode src_utils)

add_executable(crypto_tests
    tests/main.cpp
    tests/test_aes_kat.cpp
    tests/test_tdes_kat.cpp
)
target_link_libraries(crypto_tests PRIVATE src_cipher_AES src_cipher_TDES src_core src_mode src_utils gtest gtest_main)
target_include_directories(crypto_tests PRIVATE ${googletest_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/include)
gtest_discover_tests(crypto_tests)
file(COPY tests/data DESTINATION ${CMAKE_BINARY_DIR}/tests)
