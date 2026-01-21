cmake_minimum_required(VERSION 3.15)
project(project-krypto)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(OPENSSL_ROOT_DIR ${CMAKE_SOURCE_DIR}/external/openssl)
set(CRYPTOPP_ROOT_DIR ${CMAKE_SOURCE_DIR}/external/cryptopp890)
set(LIBSODIUM_ROOT_DIR ${CMAKE_SOURCE_DIR}/external/libsodium)

include_directories(
    ${CMAKE_SOURCE_DIR}/external
    ${CMAKE_SOURCE_DIR}/include
    ${OPENSSL_ROOT_DIR}/include
    ${LIBSODIUM_ROOT_DIR}/include
    ${CRYPTOPP_ROOT_DIR}
)

find_package(OpenSSL REQUIRED)

add_library(CryptoPP STATIC IMPORTED)
set_target_properties(CryptoPP PROPERTIES
    IMPORTED_LOCATION "${CRYPTOPP_ROOT_DIR}/x64/Output/Release/cryptlib.lib"
    INTERFACE_INCLUDE_DIRECTORIES "${CRYPTOPP_ROOT_DIR}"
)

add_library(sodium STATIC IMPORTED)
set_target_properties(sodium PROPERTIES
    IMPORTED_LOCATION "${LIBSODIUM_ROOT_DIR}/x64/Release/v143/static/libsodium.lib"
    INTERFACE_INCLUDE_DIRECTORIES "${LIBSODIUM_ROOT_DIR}/include"
)

if(FALSE)
include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/heads/main.zip)
FetchContent_MakeAvailable(googletest)

enable_testing()
include(GoogleTest)

endif()

add_subdirectory("bench")
add_subdirectory("bench/adapters")
add_subdirectory("src/cipher/AES")
add_subdirectory("src/cipher/TDES")
add_subdirectory("src/core")
add_subdirectory("src/mode")
add_subdirectory("src/utils")

add_executable(crypto_app_cli src/cli/cli.cpp)
target_link_libraries(crypto_app_cli PRIVATE bench bench_adapters src_cipher_AES src_cipher_TDES src_core src_mode src_utils OpenSSL::SSL OpenSSL::Crypto CryptoPP sodium)

add_executable(AES_app src/AES_main.cpp)
target_link_libraries(AES_app PRIVATE bench bench_adapters src_cipher_AES src_cipher_TDES src_core src_mode src_utils OpenSSL::SSL OpenSSL::Crypto CryptoPP sodium)

add_executable(TDES_app src/TDES_main.cpp)
target_link_libraries(TDES_app PRIVATE bench bench_adapters src_cipher_AES src_cipher_TDES src_core src_mode src_utils OpenSSL::SSL OpenSSL::Crypto CryptoPP sodium)

if(FALSE)
add_executable(crypto_tests
    tests/main.cpp
    tests/test_aes_kat.cpp
    tests/test_rng_nonce.cpp
    tests/test_tdes_kat.cpp
)

target_link_libraries(crypto_tests PRIVATE bench bench_adapters src_cipher_AES src_cipher_TDES src_core src_mode src_utils gtest gtest_main OpenSSL::SSL OpenSSL::Crypto CryptoPP sodium)
target_include_directories(crypto_tests PRIVATE ${googletest_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/include)

gtest_discover_tests(crypto_tests)

add_custom_command(
    TARGET crypto_tests POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_SOURCE_DIR}/tests/data
            ${CMAKE_BINARY_DIR}/tests/data
)

add_custom_command(
    TARGET crypto_tests POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_SOURCE_DIR}/tests/nist
            ${CMAKE_BINARY_DIR}/tests/nist
)

endif()

add_executable(bench_aes_tdes bench/bench_aes_tdes.cpp)
target_include_directories(bench_aes_tdes PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(bench_aes_tdes PRIVATE bench bench_adapters src_cipher_AES src_cipher_TDES src_core src_mode src_utils OpenSSL::SSL OpenSSL::Crypto CryptoPP sodium)

