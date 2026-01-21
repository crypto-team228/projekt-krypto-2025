# -*- coding: utf-8 -*-
import os

EXCLUDED = {"out", "build", "include","external", "scripts", "tests", "CMakeFiles"}

PROJECT_NAME = "project-krypto"

# Aplikacje
MAIN_EXECUTABLE = "crypto_app_cli"
MAIN_SOURCE = "src/cli/cli.cpp"

AES_EXECUTABLE = "AES_app"
AES_SOURCE = "src/AES_main.cpp"

TDES_EXECUTABLE = "TDES_app"
TDES_SOURCE = "src/TDES_main.cpp"

# Testy
TEST_EXECUTABLE = "crypto_tests"

# Benchmark
BENCH_EXECUTABLE = "bench_aes_tdes"
BENCH_SOURCE = "bench/bench_aes_tdes.cpp"


def generate_module_cmake(module_name, src_files):
    cmake = f"add_library({module_name}\n"
    for src in src_files:
        cmake += f"    {src}\n"
    cmake += ")\n\n"

    cmake += (
        f"target_include_directories({module_name} PUBLIC "
        "${CMAKE_SOURCE_DIR}/include "
        "${OPENSSL_ROOT_DIR}/include "
        "${LIBSODIUM_ROOT_DIR}/include "
        ")\n"
    )
    return cmake



def make_unique_module_name(dirpath):
    rel = os.path.relpath(dirpath, ".")
    return rel.replace(os.sep, "_")


def collect_test_sources():
    test_sources = []
    for dirpath, _, filenames in os.walk("tests"):
        for f in filenames:
            if f.endswith(".cpp"):
                test_sources.append(os.path.join(dirpath, f).replace(os.sep, "/"))
    return test_sources


def walk_project(root_dir):
    modules = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Pomijamy katalogi wykluczone
        if any(part in EXCLUDED for part in dirpath.split(os.sep)):
            continue

        # Pomijamy katalog glowny
        if dirpath == root_dir:
            continue

        # Zbieramy pliki .cpp (bez mainow i cli)
        src_files = [
            f
            for f in filenames
            if f.endswith(".cpp")
            and not f.endswith("_main.cpp")
            and f != "cli.cpp"
        ]

        if not src_files:
            continue

        module_name = make_unique_module_name(dirpath)
        modules.append((module_name, dirpath, src_files))

        # Generujemy CMakeLists.txt dla modulu
        cmake_path = os.path.join(dirpath, "CMakeLists.txt")
        with open(cmake_path, "w", encoding="utf-8") as f:
            f.write(generate_module_cmake(module_name, src_files))

    return modules


def generate_root_cmake(modules):
    cmake = ""
    cmake += "cmake_minimum_required(VERSION 3.15)\n"
    cmake += f"project({PROJECT_NAME})\n"
    cmake += f"set(CMAKE_MSVC_RUNTIME_LIBRARY \"MultiThreaded$<$<CONFIG:Debug>:Debug>\")\n\n"
    cmake += "set(CMAKE_CXX_STANDARD 17)\n"
    cmake += "set(CMAKE_CXX_STANDARD_REQUIRED ON)\n\n"

    cmake += "set(OPENSSL_ROOT_DIR ${CMAKE_SOURCE_DIR}/external/openssl)\n"
    cmake += "set(CRYPTOPP_ROOT_DIR ${CMAKE_SOURCE_DIR}/external/cryptopp890)\n"
    cmake += "set(LIBSODIUM_ROOT_DIR ${CMAKE_SOURCE_DIR}/external/libsodium)\n\n"

    cmake += "include_directories(\n"
    cmake += "    ${CMAKE_SOURCE_DIR}/external\n"
    cmake += "    ${CMAKE_SOURCE_DIR}/include\n"
    cmake += "    ${OPENSSL_ROOT_DIR}/include\n"
    cmake += "    ${LIBSODIUM_ROOT_DIR}/include\n"
    cmake += "    ${CRYPTOPP_ROOT_DIR}\n"
    cmake += ")\n\n"


    # OpenSSL przez find_package
    cmake += "find_package(OpenSSL REQUIRED)\n\n"
    # CryptoPP jako IMPORTED target
    cmake += "add_library(CryptoPP STATIC IMPORTED)\n"
    cmake += "set_target_properties(CryptoPP PROPERTIES\n"
    cmake += "    IMPORTED_LOCATION \"${CRYPTOPP_ROOT_DIR}/x64/Output/Release/cryptlib.lib\"\n"
    cmake += "    INTERFACE_INCLUDE_DIRECTORIES \"${CRYPTOPP_ROOT_DIR}\"\n"
    cmake += ")\n\n"

    # libsodium jako IMPORTED target
    cmake += "add_library(sodium STATIC IMPORTED)\n"
    cmake += "set_target_properties(sodium PROPERTIES\n"
    cmake += "    IMPORTED_LOCATION \"${LIBSODIUM_ROOT_DIR}/x64/Release/v143/static/libsodium.lib\"\n"
    cmake += "    INTERFACE_INCLUDE_DIRECTORIES \"${LIBSODIUM_ROOT_DIR}/include\"\n"
    cmake += ")\n\n"


    cmake += "if(FALSE)\n"
    # GoogleTest
    cmake += "include(FetchContent)\n"
    cmake += "FetchContent_Declare(\n"
    cmake += "    googletest\n"
    cmake += "    URL https://github.com/google/googletest/archive/refs/heads/main.zip"
    cmake += ")\n"
    cmake += "FetchContent_MakeAvailable(googletest)\n\n"

    cmake += "enable_testing()\n"
    cmake += "include(GoogleTest)\n\n"

    cmake += "endif()\n\n"

    # Dodajemy moduly jako subdirectory
    for module_name, path, _ in modules:
        rel_path = os.path.relpath(path, ".").replace(os.sep, "/")
        cmake += f"add_subdirectory(\"{rel_path}\")\n"
    cmake += "\n"

    # Lista nazw modulow
    module_names = " ".join([m for m, _, _ in modules])

    # Helper do dodawania aplikacji
    def add_app(name, source):
        nonlocal cmake
        cmake += f"add_executable({name} {source})\n"
        cmake += f"target_link_libraries({name} PRIVATE {module_names} OpenSSL::SSL OpenSSL::Crypto CryptoPP sodium)\n\n"

    # Aplikacje
    add_app(MAIN_EXECUTABLE, MAIN_SOURCE)
    add_app(AES_EXECUTABLE, AES_SOURCE)
    add_app(TDES_EXECUTABLE, TDES_SOURCE)

    cmake += "if(FALSE)\n"
    # Testy
    test_sources = collect_test_sources()

    cmake += f"add_executable({TEST_EXECUTABLE}\n"
    for src in test_sources:
        cmake += f"    {src}\n"
    cmake += ")\n\n"

    cmake += f"target_link_libraries({TEST_EXECUTABLE} PRIVATE {module_names} gtest gtest_main OpenSSL::SSL OpenSSL::Crypto CryptoPP sodium)\n"
    cmake += f"target_include_directories({TEST_EXECUTABLE} PRIVATE ${{googletest_SOURCE_DIR}}/include ${{CMAKE_SOURCE_DIR}}/include)\n\n"

    cmake += f"gtest_discover_tests({TEST_EXECUTABLE})\n\n"

    cmake += "add_custom_command(\n"
    cmake += f"    TARGET {TEST_EXECUTABLE} POST_BUILD\n"
    cmake += "    COMMAND ${CMAKE_COMMAND} -E copy_directory\n"
    cmake += "            ${CMAKE_SOURCE_DIR}/tests/data\n"
    cmake += "            ${CMAKE_BINARY_DIR}/tests/data\n"
    cmake += ")\n\n"

    cmake += "add_custom_command(\n"
    cmake += f"    TARGET {TEST_EXECUTABLE} POST_BUILD\n"
    cmake += "    COMMAND ${CMAKE_COMMAND} -E copy_directory\n"
    cmake += "            ${CMAKE_SOURCE_DIR}/tests/nist\n"
    cmake += "            ${CMAKE_BINARY_DIR}/tests/nist\n"
    cmake += ")\n\n"
    cmake += "endif()\n\n"

    # Benchmark
    cmake += f"add_executable({BENCH_EXECUTABLE} {BENCH_SOURCE})\n"
    cmake += f"target_include_directories({BENCH_EXECUTABLE} PRIVATE ${{CMAKE_SOURCE_DIR}}/src)\n"
    cmake += f"target_link_libraries({BENCH_EXECUTABLE} PRIVATE {module_names} OpenSSL::SSL OpenSSL::Crypto CryptoPP sodium)\n\n"

    return cmake


if __name__ == "__main__":
    modules = walk_project(".")
    with open("CMakeLists.txt", "w", encoding="utf-8") as f:
        f.write(generate_root_cmake(modules))
    print("Wygenerowano pliki CMakeLists.txt.")
