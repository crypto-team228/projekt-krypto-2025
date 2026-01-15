add_library(tests
    main.cpp
    test_aes_kat.cpp
    test_tdes_kat.cpp
)
target_include_directories(tests PUBLIC ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/external)
