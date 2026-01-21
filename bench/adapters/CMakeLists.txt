add_library(bench_adapters
    crypto_pp_adapter.cpp
    libsodium_adapter.cpp
    openssl_adapter.cpp
)

target_include_directories(bench_adapters PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
    ${CRYPTOPP_INCLUDE_DIRS}
    ${SODIUM_INCLUDE_DIRS}
)
