cmake_minimum_required(VERSION 3.15)
project(project-krypto)

enable_testing()

add_subdirectory("src")
add_subdirectory("src/classes/AES")
add_subdirectory("src/classes/TDES")
add_subdirectory("tests")

add_executable(crypto_app src/AES_main.cpp)
target_link_libraries(crypto_app PRIVATE src AES TDES tests)

add_executable(AES_app src/AES_main.cpp)
target_link_libraries(AES_app PRIVATE src AES TDES tests)

add_executable(TDES_app src/TDES_main.cpp)
target_link_libraries(TDES_app PRIVATE src AES TDES tests)

add_executable(AES_test tests/test_aes.cpp)
target_link_libraries(AES_test PRIVATE src AES TDES tests)
add_test(NAME AES_UnitTests COMMAND AES_test)

add_executable(TDES_test tests/test_tdes.cpp)
target_link_libraries(TDES_test PRIVATE src AES TDES tests)
add_test(NAME TDES_UnitTests COMMAND TDES_test)
