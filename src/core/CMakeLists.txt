add_library(src_core
    SecretKey.cpp
)

target_include_directories(src_core PUBLIC ${CMAKE_SOURCE_DIR}/include ${OPENSSL_ROOT_DIR}/include ${LIBSODIUM_ROOT_DIR}/include )
