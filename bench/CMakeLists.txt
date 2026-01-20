add_library(bench
    bench_aes_tdes.cpp
)

target_include_directories(bench PUBLIC ${CMAKE_SOURCE_DIR}/include ${OPENSSL_ROOT_DIR}/include ${LIBSODIUM_ROOT_DIR}/include )
