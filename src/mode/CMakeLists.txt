add_library(src_mode
    blockMode.cpp
    CBC.cpp
    CTR.cpp
    ECB.cpp
    GCM.cpp
)

target_include_directories(src_mode PUBLIC ${CMAKE_SOURCE_DIR}/include ${OPENSSL_ROOT_DIR}/include ${LIBSODIUM_ROOT_DIR}/include )
