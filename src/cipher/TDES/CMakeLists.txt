add_library(src_cipher_TDES
    tdes.cpp
    tdes_b.cpp
    tdes_bitslice_avx2.cpp
    tdes_bitslice_avx512_skeleton.cpp
    tdes_b_tables.cpp
    tdes_tables.cpp
)

target_include_directories(src_cipher_TDES PUBLIC ${CMAKE_SOURCE_DIR}/include ${OPENSSL_ROOT_DIR}/include ${LIBSODIUM_ROOT_DIR}/include)

# Enable AVX2/AVX512 for bitslice implementations
if(NOT MSVC)
    set_source_files_properties(tdes_bitslice_avx2.cpp PROPERTIES COMPILE_FLAGS "-mavx2")
    set_source_files_properties(tdes_bitslice_avx512_skeleton.cpp PROPERTIES COMPILE_FLAGS "-mavx512f")
else()
    set_source_files_properties(tdes_bitslice_avx2.cpp PROPERTIES COMPILE_FLAGS "/arch:AVX2")
    set_source_files_properties(tdes_bitslice_avx512_skeleton.cpp PROPERTIES COMPILE_FLAGS "/arch:AVX512")
endif()
