add_library(bench
    bench_aes_tdes.cpp
)

target_include_directories(bench PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
    ${CRYPTOPP_INCLUDE_DIRS}
    ${SODIUM_INCLUDE_DIRS}
)
