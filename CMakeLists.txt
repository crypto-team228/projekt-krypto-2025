cmake_minimum_required(VERSION 3.15)
project(project-krypto)

enable_testing()

add_subdirectory("src")
add_subdirectory("src/AES")
add_subdirectory("src/TDES")
add_subdirectory("tests")

add_executable(AES_app "src/AES_main.cpp")
add_executable(TDES_app "src/TDES_main.cpp")
target_link_libraries(AES_app PRIVATE _src _src_AES _src_TDES _tests)
target_link_libraries(TDES_app PRIVATE _src _src_AES _src_TDES _tests)
