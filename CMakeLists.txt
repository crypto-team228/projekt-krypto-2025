cmake_minimum_required(VERSION 3.15)
project(project-krypto)


    set(CMAKE_CXX_STANDARD 17)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)

    include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)
FetchContent_MakeAvailable(googletest)

enable_testing()
include(GoogleTest)

add_subdirectory("bench")
add_subdirectory("src/cipher/AES")
add_subdirectory("src/cipher/TDES")
add_subdirectory("src/core")
add_subdirectory("src/mode")
add_subdirectory("src/utils")

add_executable(crypto_app_cli src/cli/cli.cpp)
target_link_libraries(crypto_app_cli PRIVATE bench src_cipher_AES src_cipher_TDES src_core src_mode src_utils)

add_executable(AES_app src/AES_main.cpp)
target_link_libraries(AES_app PRIVATE bench src_cipher_AES src_cipher_TDES src_core src_mode src_utils)

add_executable(TDES_app src/TDES_main.cpp)
target_link_libraries(TDES_app PRIVATE bench src_cipher_AES src_cipher_TDES src_core src_mode src_utils)

add_executable(crypto_tests
    tests/main.cpp
    tests/test_aes_kat.cpp
    tests/test_rng_nonce.cpp
    tests/test_tdes_kat.cpp
)
target_link_libraries(crypto_tests PRIVATE bench src_cipher_AES src_cipher_TDES src_core src_mode src_utils gtest gtest_main)
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
        add_executable(bench_aes_tdes bench/bench_aes_tdes.cpp)
target_include_directories(bench_aes_tdes PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(bench_aes_tdes PRIVATE bench src_cipher_AES src_cipher_TDES src_core src_mode src_utils)
