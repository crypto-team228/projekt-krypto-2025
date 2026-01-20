add_executable(crypto_bench
    bench_aes_tdes.cpp
)
target_include_directories(crypto_bench PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/external)
target_link_libraries(crypto_bench PRIVATE src_cipher_AES src_cipher_TDES src_mode)
