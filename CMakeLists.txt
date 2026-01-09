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

add_executable(AES_test tests/test_aes.cpp)
target_link_libraries(AES_test PRIVATE src_cipher_AES src_cipher_TDES src_core src_mode src_utils gtest gtest_main)
target_include_directories(AES_test PRIVATE ${gtest_SOURCE_DIR}/include)
gtest_discover_tests(AES_test)

add_executable(TDES_test tests/test_tdes.cpp)
target_link_libraries(TDES_test PRIVATE src_cipher_AES src_cipher_TDES src_core src_mode src_utils gtest gtest_main)
target_include_directories(TDES_test PRIVATE ${gtest_SOURCE_DIR}/include)
gtest_discover_tests(TDES_test)
