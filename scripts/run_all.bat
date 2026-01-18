@echo off
setlocal enabledelayedexpansion

set BUILD_DIR=build

echo [*] Konfiguracja CMake (Release)…
cmake -S . -B %BUILD_DIR% -DCMAKE_BUILD_TYPE=Release

echo [*] Budowanie…
cmake --build %BUILD_DIR% --config Release

echo [*] Testy jednostkowe…
cd %BUILD_DIR%
ctest --output-on-failure

echo [*] Benchmarki…
if exist bench\bench_aes_tdes.exe (
  bench\bench_aes_tdes.exe --output ..\bench_results.csv
) else (
  echo Brak bench\bench_aes_tdes.exe – zbuduj target bench_aes_tdes.
)

echo [*] Gotowe. Wyniki benchmarków: bench_results.csv
endlocal
