#include "utils/CounterNonce.hpp"
#include <fstream>

namespace utils {

    CounterNonceGenerator::CounterNonceGenerator(
        uint64_t startValue,
        const std::string& persistFile
    )
        : counter(startValue), file(persistFile) {
    }

    CounterNonceGenerator::~CounterNonceGenerator() {
        save();
    }

    std::vector<uint8_t> CounterNonceGenerator::generate(size_t size) {
        // Nonce oparty na monotonicznym liczniku (big-endian)
        std::vector<uint8_t> nonce(size, 0);

        // Zapisujemy licznik w pierwszych 8 bajtach (jeœli siê mieszcz¹)
        for (size_t i = 0; i < size && i < 8; ++i) {
            nonce[i] = static_cast<uint8_t>(
                (counter >> ((7 - i) * 8)) & 0xFF
                );
        }

        ++counter;
        save();
        return nonce;
    }

    void CounterNonceGenerator::load() {
        if (file.empty())
            return;

        std::ifstream in(file, std::ios::binary);
        if (in.is_open()) {
            in.read(reinterpret_cast<char*>(&counter), sizeof(counter));
        }
    }

    void CounterNonceGenerator::save() const {
        if (file.empty())
            return;

        std::ofstream out(file, std::ios::binary);
        if (out.is_open()) {
            out.write(reinterpret_cast<const char*>(&counter), sizeof(counter));
        }
    }

} // namespace utils
