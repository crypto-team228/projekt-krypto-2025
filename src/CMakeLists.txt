add_library(src
    AES_main.cpp
    TDES_main.cpp
 "utils/cipherFactory.cpp" "utils/modeFactory.cpp" "mode/CBC.cpp" "mode/CTR.cpp" "mode/ECB.cpp")
target_include_directories(src PUBLIC ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/external)
