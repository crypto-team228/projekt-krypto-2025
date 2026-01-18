#!/usr/bin/env bash
set -euo pipefail

BUILD_DIR="build"

echo "[*] Konfiguracja CMake (Release)…"
cmake -S . -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release

echo "[*] Budowanie…"
cmake --build "$BUILD_DIR" --config Release

echo "[*] Testy jednostkowe…"
cd "$BUILD_DIR"
ctest --output-on-failure

echo "[*] Benchmarki…"
if [ -x "./bench/bench_aes_tdes" ]; then
  ./bench/bench_aes_tdes --output ../bench_results.csv
else
  echo "Brak ./bench/bench_aes_tdes – zbuduj target bench_aes_tdes."
fi

echo "[*] Gotowe. Wyniki benchmarków: bench_results.csv"
