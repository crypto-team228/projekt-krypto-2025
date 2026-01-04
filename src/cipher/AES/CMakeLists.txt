add_library(src_cipher_AES
    aes.cpp
)
target_include_directories(src_cipher_AES PUBLIC ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/external)
