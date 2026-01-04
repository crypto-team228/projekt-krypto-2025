cmake_minimum_required(VERSION 3.15)
project(project-krypto)

add_subdirectory("src")
add_subdirectory("src/cipher/AES")
add_subdirectory("src/cipher/TDES")
add_subdirectory("src/cli")
add_subdirectory("src/mode")
add_subdirectory("src/utils")
add_subdirectory("tests")

add_executable(crypto_app_cli src/cli/cli.cpp)
target_link_libraries(crypto_app_cli PRIVATE src src_cipher_AES src_cipher_TDES src_cli src_mode src_utils tests)

add_executable(AES_app src/AES_main.cpp)
target_link_libraries(AES_app PRIVATE src src_cipher_AES src_cipher_TDES src_cli src_mode src_utils tests)

add_executable(TDES_app src/TDES_main.cpp)
target_link_libraries(TDES_app PRIVATE src src_cipher_AES src_cipher_TDES src_cli src_mode src_utils tests)

add_executable(AES_test tests/test_aes.cpp)
target_link_libraries(AES_test PRIVATE src src_cipher_AES src_cipher_TDES src_cli src_mode src_utils tests)

add_executable(TDES_test tests/test_tdes.cpp)
target_link_libraries(TDES_test PRIVATE src src_cipher_AES src_cipher_TDES src_cli src_mode src_utils tests)
