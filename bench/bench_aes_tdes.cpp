#include <chrono>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <iomanip>

#include "cipher/AES/aes.hpp"
#include "cipher/TDES/tdes.hpp"
#include "mode/ECB.hpp"
#include "mode/CBC.hpp"
#include "mode/CTR.hpp"
#include "mode/GCM.hpp"

using Clock = std::chrono::high_resolution_clock;

struct BenchResult {
    std::string algo;
    std::string mode;
    size_t size;
    double mbps;
    double usec_per_op;
};

static void fillPattern(std::vector<uint8_t>& v, uint8_t seed) {
    for (size_t i = 0; i < v.size(); ++i)
        v[i] = static_cast<uint8_t>(seed + i);
}

template<typename Mode, typename CipherT>
BenchResult bench_mode(const std::string& algo,
    const std::string& modeName,
    CipherT& cipher,
    size_t keySize,
    size_t ivSize,
    size_t dataSize,
    size_t iters)
{
    Mode mode;

    // Create proper-sized key
    std::vector<uint8_t> key(keySize);
    fillPattern(key, 0x11);
    cipher.setKey(key);

    // Create and set IV for modes that need it
    std::vector<uint8_t> iv(ivSize);
    fillPattern(iv, 0x22);

    if constexpr (std::is_same_v<Mode, GCM>) {
        mode.setIV(iv);
    } else if constexpr (std::is_same_v<Mode, CBC>) {
        mode.setIV(iv);
    } else if constexpr (std::is_same_v<Mode, CTR>) {
        mode.setIV(iv);
    }
    // ECB doesn't need IV

    // Create plaintext
    std::vector<uint8_t> pt(dataSize);
    fillPattern(pt, 0x33);

    // Warmup
    auto ct = mode.encrypt(pt, cipher);

    // Benchmark
    auto start = Clock::now();
    for (size_t i = 0; i < iters; ++i) {
        ct = mode.encrypt(pt, cipher);
    }
    auto end = Clock::now();

    auto dur = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    double seconds = dur / 1e6;
    double total_bytes = static_cast<double>(dataSize) * iters;
    double mbps = (total_bytes / (1024.0 * 1024.0)) / seconds;
    double usec_per_op = static_cast<double>(dur) / iters;

    return { algo, modeName, dataSize, mbps, usec_per_op };
}

int main(int argc, char** argv)
{
    std::string outFile = "bench_results.csv";
    size_t iters = 100;

    // Parse CLI args
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            outFile = argv[++i];
        } else if (std::strcmp(argv[i], "--iters") == 0 && i + 1 < argc) {
            iters = std::stoul(argv[++i]);
        }
    }

    std::vector<size_t> sizes = { 1024, 4096, 16384, 65536, 262144 };
    std::vector<BenchResult> results;

    // Create ciphers (key will be set in bench_mode)
    AES aes128;
    AES aes256;
    TDES tdes;

    std::cerr << "[*] Starting benchmarks (iters=" << iters << ")...\n";

    for (auto size : sizes) {
        // AES-128 (key=16, iv=16)
        std::cerr << "[*] AES-128 ECB size=" << size << "\n";
        results.push_back(bench_mode<ECB>("AES-128", "ECB", aes128, 16, 16, size, iters));
        std::cerr << "[*] AES-128 CBC size=" << size << "\n";
        results.push_back(bench_mode<CBC>("AES-128", "CBC", aes128, 16, 16, size, iters));
        std::cerr << "[*] AES-128 CTR size=" << size << "\n";
        results.push_back(bench_mode<CTR>("AES-128", "CTR", aes128, 16, 16, size, iters));
        std::cerr << "[*] AES-128 GCM size=" << size << "\n";
        results.push_back(bench_mode<GCM>("AES-128", "GCM", aes128, 16, 16, size, iters));

        // AES-256 (key=32, iv=16)
        std::cerr << "[*] AES-256 ECB size=" << size << "\n";
        results.push_back(bench_mode<ECB>("AES-256", "ECB", aes256, 32, 16, size, iters));
        std::cerr << "[*] AES-256 CBC size=" << size << "\n";
        results.push_back(bench_mode<CBC>("AES-256", "CBC", aes256, 32, 16, size, iters));
        std::cerr << "[*] AES-256 CTR size=" << size << "\n";
        results.push_back(bench_mode<CTR>("AES-256", "CTR", aes256, 32, 16, size, iters));
        std::cerr << "[*] AES-256 GCM size=" << size << "\n";
        results.push_back(bench_mode<GCM>("AES-256", "GCM", aes256, 32, 16, size, iters));

        // TDES (key=24, block=8) - only ECB supported (CBC/CTR/GCM require 16-byte IV)
        std::cerr << "[*] TDES ECB size=" << size << "\n";
        results.push_back(bench_mode<ECB>("TDES", "ECB", tdes, 24, 8, size, iters));
    }

    // Write CSV
    std::ofstream ofs(outFile);
    ofs << "algo,mode,size_bytes,throughput_MBps,latency_usec\n";
    for (auto& r : results) {
        ofs << r.algo << ","
            << r.mode << ","
            << r.size << ","
            << std::fixed << std::setprecision(2) << r.mbps << ","
            << std::fixed << std::setprecision(2) << r.usec_per_op << "\n";
    }

    // Print summary to console
    std::cerr << "\n[*] Results saved to " << outFile << "\n";
    std::cerr << "\n=== Summary ===\n";
    std::cerr << std::left << std::setw(12) << "Algorithm"
              << std::setw(6) << "Mode"
              << std::setw(12) << "Size"
              << std::setw(14) << "Throughput"
              << "Latency\n";
    std::cerr << std::string(54, '-') << "\n";
    for (auto& r : results) {
        std::cerr << std::left << std::setw(12) << r.algo
                  << std::setw(6) << r.mode
                  << std::setw(12) << r.size
                  << std::fixed << std::setprecision(2)
                  << std::setw(10) << r.mbps << " MB/s"
                  << std::setw(10) << r.usec_per_op << " us\n";
    }

    return 0;
}
