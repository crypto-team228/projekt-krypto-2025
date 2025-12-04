import os

excluded = {"out", "build"}

PROJECT_NAME = "project-krypto"
MAIN_EXECUTABLE = "crypto_app"
MAIN_SOURCE = os.path.join("src", "AES_main.cpp")

TDES_EXECUTABLE = "TDES_app"
TDES_SOURCE = os.path.join("src", "TDES_main.cpp")
TDES_TEST_EXECUTABLE = "TDES_test"
TDES_TEST = os.path.join("tests", "test_tdes.cpp")

AES_EXECUTABLE = "AES_app"
AES_SOURCE = os.path.join("src", "AES_main.cpp")
AES_TEST_EXECUTABLE = "AES_test"
AES_TEST = os.path.join("tests", "test_aes.cpp")




def generate_module_cmake(module_name, src_files):
    cmake = f"add_library({module_name}\n"
    for src in src_files:
        cmake += f"    {src.replace(os.sep, '/')}\n"
    cmake += ")\n"
    cmake += f"target_include_directories({module_name} PUBLIC ${{CMAKE_SOURCE_DIR}}/include)\n"

    return cmake

def walk_project(root_dir):
    modules = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        if any(part in excluded for part in dirpath.split(os.sep)):
            continue
        if dirpath == root_dir:
            continue

        src_files = [f for f in filenames if f.endswith(".cpp")]
        if src_files:
            module_name = os.path.basename(dirpath)
            modules.append((module_name, dirpath, src_files))
            cmake_path = os.path.join(dirpath, "CMakeLists.txt")
            with open(cmake_path, "w") as f:
                f.write(generate_module_cmake(module_name, src_files))
    return modules

def generate_root_cmake(modules):
    cmake = "cmake_minimum_required(VERSION 3.15)\n"
    cmake += f"project({PROJECT_NAME})\n\n"
    for _, path, _ in modules:
        rel_path = os.path.relpath(path, ".").replace(os.sep, "/")
        cmake += f"add_subdirectory(\"{rel_path}\")\n"

    # Main
    cmake += f"\nadd_executable({MAIN_EXECUTABLE} {MAIN_SOURCE.replace(os.sep, '/')})\n"
    cmake += f"target_link_libraries({MAIN_EXECUTABLE} PRIVATE "
    cmake += " ".join([m for m, _, _ in modules])
    cmake += ")\n"

    #AES
    cmake += f"\nadd_executable({AES_EXECUTABLE} {AES_SOURCE.replace(os.sep, '/')})\n"
    cmake += f"target_link_libraries({AES_EXECUTABLE} PRIVATE "
    cmake += " ".join([m for m, _, _ in modules])
    cmake += ")\n"

    #TDES
    cmake += f"\nadd_executable({TDES_EXECUTABLE} {TDES_SOURCE.replace(os.sep, '/')})\n"
    cmake += f"target_link_libraries({TDES_EXECUTABLE} PRIVATE "
    cmake += " ".join([m for m, _, _ in modules])
    cmake += ")\n"
        
    # --- Tests
    #AES
    cmake += f"\nadd_executable({AES_TEST_EXECUTABLE} {AES_TEST.replace(os.sep, '/')})\n"
    cmake += f"target_link_libraries({AES_TEST_EXECUTABLE} PRIVATE "
    cmake += " ".join([m for m, _, _ in modules])
    cmake += ")\n"

    #TDES
    cmake += f"\nadd_executable({TDES_TEST_EXECUTABLE} {TDES_TEST.replace(os.sep, '/')})\n"
    cmake += f"target_link_libraries({TDES_TEST_EXECUTABLE} PRIVATE "
    cmake += " ".join([m for m, _, _ in modules])
    cmake += ")\n"


    return cmake


if __name__ == "__main__":
    root = "."
    modules = walk_project(root)
    with open("CMakeLists.txt", "w", encoding="utf-8") as f:
        f.write(generate_root_cmake(modules))
    print("Wygenerowano pliki CMakeLists.txt dla projektu.")
