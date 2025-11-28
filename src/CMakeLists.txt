add_library(_src
    AES_main.cpp
    TDES_main.cpp
)
target_include_directories(_src PUBLIC ${CMAKE_SOURCE_DIR}/include)
