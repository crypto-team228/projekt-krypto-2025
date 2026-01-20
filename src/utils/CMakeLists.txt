add_library(src_utils
    cipherFactory.cpp
    CounterNonce.cpp
    modeFactory.cpp
    Nonce.cpp
    RNG.cpp
)
target_include_directories(src_utils PUBLIC ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/external)
target_link_libraries(src_utils PUBLIC src_cipher_AES src_cipher_TDES src_mode)
