add_library(_src_TDES
    tdes.cpp
    tdes_tables.cpp
)
target_include_directories(_src_TDES PUBLIC ${CMAKE_SOURCE_DIR}/include)
