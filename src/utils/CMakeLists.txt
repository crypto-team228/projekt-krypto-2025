add_library(src_utils
    cipherFactory.cpp
    CounterNonce.cpp
    modeFactory.cpp
    Nonce.cpp
    RNG.cpp
)

target_include_directories(src_utils PUBLIC ${CMAKE_SOURCE_DIR}/include ${OPENSSL_ROOT_DIR}/include ${LIBSODIUM_ROOT_DIR}/include )
