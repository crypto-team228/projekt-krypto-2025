add_library(src_cipher_TDES
 tdes.cpp
 tdes_tables.cpp
)
target_include_directories(src_cipher_TDES PUBLIC ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/external)
