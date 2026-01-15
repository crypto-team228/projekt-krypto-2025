#include <mode/CBC.hpp>
#include <stdexcept>

std::vector<uint8_t> CBC::encrypt(const std::vector<uint8_t>& data, Cipher& cipher) {
    // Implement CBC encryption logic here
    return data;
}

std::vector<uint8_t> CBC::decrypt(const std::vector<uint8_t>& data, Cipher& cipher) {
    // Implement CBC decryption logic here
    return data;
}
void CBC::setIV(const std::vector<uint8_t>& initVector)
{
    if (initVector.size() != 16)
    {
        throw std::invalid_argument("IV must be 16 bytes");
    }
    std::copy(initVector.begin(), initVector.end(), iv.begin());
}