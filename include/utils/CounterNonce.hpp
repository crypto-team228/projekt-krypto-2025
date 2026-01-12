#pragma once
#include <vector>
#include <cstdint>
#include <string>

namespace utils {

    class CounterNonceGenerator {
    public:
        // startValue – pocz¹tkowa wartoœæ licznika
        // persistFile – plik do zapisu licznika (opcjonalny)
        CounterNonceGenerator(
            uint64_t startValue = 0,
            const std::string& persistFile = ""
        );

        ~CounterNonceGenerator();

        // Generuje nonce o zadanej d³ugoœci
        std::vector<uint8_t> generate(size_t size);
        // Wczytuje licznik z pliku (jeœli istnieje)
        void load();
        // Zapisuje aktualny licznik do pliku
        void save() const;

    private:
        uint64_t counter;
        std::string file;
    };

} // namespace utils
