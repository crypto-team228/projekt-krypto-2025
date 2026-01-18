#!/usr/bin/env python3
import subprocess
import csv
from pathlib import Path

BUILD_DIR = Path("build")
BENCH_BIN = BUILD_DIR / "bench" / "bench_aes_tdes"
OUT_CSV = Path("bench_results.csv")

def run():
    if not BENCH_BIN.exists():
        raise SystemExit(f"Brak {BENCH_BIN}, zbuduj projekt.")

    subprocess.check_call([str(BENCH_BIN), "--output", str(OUT_CSV)])
    print(f"[*] Wyniki zapisane w {OUT_CSV}")

    # szybki podgl¹d
    with OUT_CSV.open() as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    print("[*] Przyk³adowe wiersze:")
    for r in rows[:5]:
        print(r)

if __name__ == "__main__":
    run()
