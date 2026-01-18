#include <chrono>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>

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
    size_t size,
    size_t iters)
{
    Mode mode;
    const size_t blockSize = cipher.blockSize();

    std::vector<uint8_t> key(cipher.blockSize());
    std::vector<uint8_t> iv(blockSize);
    fillPattern(key, 0x11);
    fillPattern(iv, 0x22);

    cipher.setKey(key);
    if constexpr (std::is_same_v<Mode, GCM>) {
        mode.setIV(iv);
    }
	else if constexpr (!std::is_same_v<Mode, ECB>){

    }

    std::vector<uint8_t> pt(size);
    fillPattern(pt, 0x33);

    // warmup
    auto ct = mode.encrypt(pt, cipher);

    auto start = Clock::now();
    for (size_t i = 0; i < iters; ++i) {
        ct = mode.encrypt(pt, cipher);
    }
    auto end = Clock::now();

    auto dur = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    double seconds = dur / 1e6;
    double total_bytes = static_cast<double>(size) * iters;
    double mbps = (total_bytes / (1024.0 * 1024.0)) / seconds;
    double usec_per_op = static_cast<double>(dur) / iters;

    return { algo, modeName, size, mbps, usec_per_op };
}

int main(int argc, char** argv)
{
    std::string outFile = "bench_results.csv";
    if (argc > 1 && std::strcmp(argv[1], "--output") == 0 && argc > 2) {
        outFile = argv[2];
    }

    std::vector<size_t> sizes = { 1024, 4096, 16384, 65536, 1048576 };
    size_t iters = 1000;

    std::vector<BenchResult> results;

    AES aes128(std::vector<uint8_t>(16, 0x00));
    AES aes256(std::vector<uint8_t>(32, 0x00));
    TDES tdes(std::vector<uint8_t>(24, 0x00)); // 3×8 bajtów

    for (auto size : sizes) {
        results.push_back(bench_mode<ECB>("AES-128", "ECB", aes128, size, iters));
        results.push_back(bench_mode<CBC>("AES-128", "CBC", aes128, size, iters));
        results.push_back(bench_mode<CTR>("AES-128", "CTR", aes128, size, iters));
        results.push_back(bench_mode<GCM>("AES-128", "GCM", aes128, size, iters));

        results.push_back(bench_mode<ECB>("AES-256", "ECB", aes256, size, iters));
        results.push_back(bench_mode<CBC>("AES-256", "CBC", aes256, size, iters));
        results.push_back(bench_mode<CTR>("AES-256", "CTR", aes256, size, iters));
        results.push_back(bench_mode<GCM>("AES-256", "GCM", aes256, size, iters));

        results.push_back(bench_mode<ECB>("TDES", "ECB", tdes, size, iters));
        results.push_back(bench_mode<CBC>("TDES", "CBC", tdes, size, iters));
    }

    std::ofstream ofs(outFile);
    ofs << "algo,mode,size_bytes,throughput_MBps,latency_usec\n";
    for (auto& r : results) {
        ofs << r.algo << ","
            << r.mode << ","
            << r.size << ","
            << r.mbps << ","
            << r.usec_per_op << "\n";
    }

    std::cerr << "[*] Zapisano wyniki do " << outFile << "\n";
    return 0;
}
