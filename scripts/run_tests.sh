#!/usr/bin/env bash
set -euo pipefail

BUILD_DIR=${BUILD_DIR:-build}
RUNS=${RUNS:-5}

echo "[*] Configuring..."
cmake -S . -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=RelWithDebInfo

echo "[*] Building crypto_tests..."
cmake --build "$BUILD_DIR" --target crypto_tests -j"$(nproc)"

mkdir -p out/test_runs

EXIT_CODE=0

for i in $(seq 1 "$RUNS"); do
    echo "=== TEST RUN #$i ==="
    LOG_FILE="out/test_runs/tests_run_${i}.log"

    if ! "$BUILD_DIR/crypto_tests" | tee "$LOG_FILE"; then
        echo "Run #$i FAILED"
        EXIT_CODE=1
    fi

    echo
done

exit "$EXIT_CODE"
