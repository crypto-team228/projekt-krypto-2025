#pragma once
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include "utils/DataConverter.hpp"

// Jeden case KAT: key/pt/ct w bajtach
struct KATCase {
    std::string name;
    std::vector<uint8_t> key;
    std::vector<uint8_t> plaintext;
    std::vector<uint8_t> ciphertext;
};

// Proste CSV: name,key,plaintext,ciphertext (hex)
inline std::vector<KATCase> LoadKATFile(const std::string& path)
{
    std::ifstream in(path);
    if (!in) {
        throw std::runtime_error("Cannot open KAT file: " + path);
    }

    std::vector<KATCase> result;
    std::string line;

    // pomiñ nag³ówek
    if (!std::getline(in, line)) {
        return result;
    }

    while (std::getline(in, line)) {
        if (line.empty()) continue;

        std::stringstream ss(line);
        std::string name, keyHex, ptHex, ctHex;

        if (!std::getline(ss, name, ',')) continue;
        if (!std::getline(ss, keyHex, ',')) continue;
        if (!std::getline(ss, ptHex, ',')) continue;
        if (!std::getline(ss, ctHex, ',')) continue;

        KATCase tc;
        tc.name = name;
        tc.key = DataConverter::HexToBytes(keyHex);
        tc.plaintext = DataConverter::HexToBytes(ptHex);
        tc.ciphertext = DataConverter::HexToBytes(ctHex);

        result.push_back(std::move(tc));
    }

    return result;
}
