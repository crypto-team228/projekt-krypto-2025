#include "CLI/CLI.hpp"
#include <string>
#include <vector>
#include <iostream>

// --- Twoje funkcje normalizuj¹ce ---
std::vector<uint8_t> decode(const std::string& input, const std::string& encoding) {
    if (encoding == "utf8") {
        return std::vector<uint8_t>(input.begin(), input.end());
    }
    if (encoding == "hex") {
        std::vector<uint8_t> out;
        out.reserve(input.size() / 2);
        for (size_t i = 0; i < input.size(); i += 2) {
            out.push_back(std::stoi(input.substr(i, 2), nullptr, 16));
        }
        return out;
    }
    if (encoding == "base64") {
        // tu mo¿esz podpi¹æ swoj¹ funkcjê base64_decode
        throw std::runtime_error("base64 not implemented");
    }
    throw std::runtime_error("Unknown encoding: " + encoding);
}

int main(int argc, char** argv) {
    CLI::App app{ "Crypto CLI" };

    std::string text;
    std::string text_encoding = "utf8";

    std::string key;
    std::string key_encoding = "hex";

    std::string mode = "CBC";
    std::string iv;

    // --- Definicje argumentów ---
    app.add_option("--text", text, "Tekst do zaszyfrowania")->required();
    app.add_option("--text-encoding", text_encoding, "Kodowanie tekstu (utf8, hex, base64)");

    app.add_option("--key", key, "Klucz")->required();
    app.add_option("--key-encoding", key_encoding, "Kodowanie klucza (hex, utf8, base64)");

    app.add_option("--mode", mode, "Tryb szyfrowania (CBC, ECB, CTR, GCM)");
    app.add_option("--iv", iv, "Wektor inicjalizuj¹cy (hex)");

    CLI11_PARSE(app, argc, argv);

    // --- Normalizacja wejœcia ---
    auto plaintext_bytes = decode(text, text_encoding);
    auto key_bytes = decode(key, key_encoding);
    auto iv_bytes = iv.empty() ? std::vector<uint8_t>() : decode(iv, "hex");

    // --- Wywo³anie Twojej funkcji szyfruj¹cej ---
    // ModeFactory::create(mode)->encryptBlock(plaintext_bytes, key_bytes, iv_bytes);

    std::cout << "CLI dzia³a poprawnie, dane znormalizowane." << std::endl;
}
