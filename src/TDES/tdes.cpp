#include "TDES/tdes.hpp"

TDES::TDES() {

}

std::string TDES::encrypt(std::string plainText) {

	return 0;
}

std::string TDES::decrypt(std::string ciphrtText) {

	return 0;
}

std::array<uint8_t, 64> TDES::test(std::array<uint8_t,64> str) {
    std::array<uint8_t, 64> result{};
    result = permute(initialPermutation,str);
    return result;
}

template <std::size_t N, std::size_t M>
std::array<std::uint8_t, N> TDES::permute(const std::array<uint8_t, N>& table,
    const std::array<std::uint8_t, M>& input) {
    std::array<std::uint8_t, N> result{};
    for (std::size_t i = 0; i < N; i++) {
        result[i] = input[table[i]];
    }
    return result;
}
