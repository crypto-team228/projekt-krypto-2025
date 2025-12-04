add_library(TDES
    tdes.cpp
    tdes_tables.cpp
)
target_include_directories(TDES PUBLIC ${CMAKE_SOURCE_DIR}/include)
