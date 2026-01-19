# -*- coding: utf-8 -*-
import os

EXCLUDED = {"out", "build", "include", "external", "scripts","tests"}

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


def generate_module_cmake(module_name, src_files):
    cmake = f"add_library({module_name}\n"
    for src in src_files:
        cmake += f" {src}\n"
    cmake += ")\n"
    cmake += (
        f"target_include_directories({module_name} PUBLIC "
        "${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/external)\n"
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

        # Zbieramy pliki .cpp
        src_files = [
            f
            for f in filenames
            if f.endswith(".cpp") and not f.endswith("_main.cpp") and f != "cli.cpp"
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
    cmake = "cmake_minimum_required(VERSION 3.15)\n"
    cmake += f"project({PROJECT_NAME})\n\n"
    cmake += """
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(OPENSSL_ROOT_DIR ${CMAKE_SOURCE_DIR}/external/OpenSSL)
set(CRYPTOPP_ROOT_DIR ${CMAKE_SOURCE_DIR}/external/cryptopp890)
set(LIBSODIUM_ROOT_DIR ${CMAKE_SOURCE_DIR}/external/libsodium)

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/external

    ${OPENSSL_ROOT_DIR}/include
    ${CRYPTOPP_ROOT_DIR}
    ${LIBSODIUM_ROOT_DIR}/include
)

link_directories(
    ${OPENSSL_ROOT_DIR}/lib
    ${CRYPTOPP_ROOT_DIR}/x64/Output/Release
    ${LIBSODIUM_ROOT_DIR}/x64/Release/v143/static
)
"""

    # GoogleTest
    cmake += "include(FetchContent)\n"
    cmake += "FetchContent_Declare(\n"
    cmake += "    googletest\n"
    cmake += "    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip\n"
    cmake += ")\n"
    cmake += "FetchContent_MakeAvailable(googletest)\n\n"

    cmake += "enable_testing()\n"
    cmake += "include(GoogleTest)\n\n"

    # Dodajemy moduly
    for module_name, path, _ in modules:
        rel_path = os.path.relpath(path, ".").replace(os.sep, "/")
        cmake += f"add_subdirectory(\"{rel_path}\")\n"

    # Aplikacje
    def add_app(name, source):
        nonlocal cmake
        cmake += f"\nadd_executable({name} {source})\n"
        cmake += f"target_link_libraries({name} PRIVATE "
        cmake += " ".join([m for m, _, _ in modules])
        cmake += ")\n"

    add_app(MAIN_EXECUTABLE, MAIN_SOURCE)
    add_app(AES_EXECUTABLE, AES_SOURCE)
    add_app(TDES_EXECUTABLE, TDES_SOURCE)

    test_sources = collect_test_sources()

    cmake += f"\nadd_executable({TEST_EXECUTABLE}\n"
    for src in test_sources:
        cmake += f"    {src}\n"
    cmake += ")\n"

    cmake += "target_link_libraries(" + TEST_EXECUTABLE + " PRIVATE "
    cmake += " ".join([m for m, _, _ in modules])
    cmake += " gtest gtest_main)\n"

    cmake += "target_include_directories(" + TEST_EXECUTABLE + " PRIVATE "
    cmake += "${googletest_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/include)\n"

    cmake += f"gtest_discover_tests({TEST_EXECUTABLE})\n"
    cmake += """
add_custom_command(
    TARGET """ + TEST_EXECUTABLE + """ POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_SOURCE_DIR}/tests/data
            ${CMAKE_BINARY_DIR}/tests/data
)

add_custom_command(
    TARGET """ + TEST_EXECUTABLE + """ POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_SOURCE_DIR}/tests/nist
            ${CMAKE_BINARY_DIR}/tests/nist
)
"""

    # Benchmark
    cmake += "add_executable(bench_aes_tdes bench/bench_aes_tdes.cpp)\n"
    cmake += "target_include_directories(bench_aes_tdes PRIVATE ${CMAKE_SOURCE_DIR}/src)\n"
    cmake += "target_link_libraries(bench_aes_tdes PRIVATE "
    cmake += " ".join([m for m, _, _ in modules])
    cmake += " crypto libcrypto libssl cryptopp libsodium)\n"

    return cmake


if __name__ == "__main__":
    modules = walk_project(".")
    with open("CMakeLists.txt", "w", encoding="utf-8") as f:
        f.write(generate_root_cmake(modules))
    print("Wygenerowano pliki CMakeLists.txt.")
