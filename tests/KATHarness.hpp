#pragma once
#include "KATHarness.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>

// Jeden case KAT: key/pt/ct w bajtach
#pragma once
#include <string>
#include <vector>
#include <cstdint>

struct KATCase {
    std::string name;
    std::vector<uint8_t> key;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> aad;
    std::vector<uint8_t> plaintext;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> tag;
};

inline static std::string BytesToHex(const std::vector<uint8_t>& v) {
    std::ostringstream oss;
    for (auto b : v)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return oss.str();
}

static std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    auto end = s.find_last_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    return s.substr(start, end - start + 1);
}

inline std::vector<uint8_t> HexToBytes(const std::string& hex) {
    std::vector<uint8_t> out;
    if (hex.size() % 2 != 0) return out;

    for (size_t i = 0; i < hex.size(); i += 2) {
        uint8_t b = static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16));
        out.push_back(b);
    }
    return out;
}

inline std::vector<KATCase> LoadKATFile(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return {};

    std::vector<KATCase> cases;
    std::string line;

    // skip header
    std::getline(f, line);

    while (std::getline(f, line)) {
        if (trim(line).empty()) continue;

        std::stringstream ss(line);
        std::string name, key, iv, aad, pt, ct, tag;

        std::getline(ss, name, ',');
        std::getline(ss, key, ',');
        std::getline(ss, iv, ',');
        std::getline(ss, aad, ',');
        std::getline(ss, pt, ',');
        std::getline(ss, ct, ',');
        std::getline(ss, tag, ',');

        KATCase tc;
        tc.name = trim(name);
        tc.key = HexToBytes(trim(key));
        tc.iv = HexToBytes(trim(iv));
        tc.aad = HexToBytes(trim(aad));
        tc.plaintext = HexToBytes(trim(pt));
        tc.ciphertext = HexToBytes(trim(ct));
        tc.tag = HexToBytes(trim(tag));

        cases.push_back(tc);
    }

    return cases;
}
