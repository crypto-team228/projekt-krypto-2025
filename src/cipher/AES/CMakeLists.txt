add_library(src_cipher_AES
    aes.cpp
)

target_include_directories(src_cipher_AES PUBLIC ${CMAKE_SOURCE_DIR}/include ${OPENSSL_ROOT_DIR}/include ${LIBSODIUM_ROOT_DIR}/include )
