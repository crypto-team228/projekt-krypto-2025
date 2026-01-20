add_library(src_cipher_TDES
    tdes.cpp
    tdes_b.cpp
    tdes_bitslice_avx512_skeleton.cpp
    tdes_b_tables.cpp
    tdes_tables.cpp
 "tdes_bitslice_avx2.cpp")

target_include_directories(src_cipher_TDES PUBLIC ${CMAKE_SOURCE_DIR}/include ${OPENSSL_ROOT_DIR}/include ${LIBSODIUM_ROOT_DIR}/include )
