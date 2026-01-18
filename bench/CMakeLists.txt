add_library(bench
    bench_aes_tdes.cpp
)
target_include_directories(bench PUBLIC ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/external)
