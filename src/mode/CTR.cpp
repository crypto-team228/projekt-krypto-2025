#include <mode/CTR.hpp>
#include "cipher/cipher.hpp"
#include <stdexcept>

std::vector<uint8_t> CTR::encrypt(const std::vector<uint8_t>& data, Cipher& cipher) {
    // Implement CTR encryption logic here
    return data;
}

std::vector<uint8_t> CTR::decrypt(const std::vector<uint8_t>& data, Cipher& cipher) {
    // Implement CTR decryption logic here
    return data;
}
void CTR::setIV(const std::vector<uint8_t>& initVector)
{
    if (initVector.size() != 16)
    {
        throw std::invalid_argument("IV must be 16 bytes");
    }
    std::copy(initVector.begin(), initVector.end(), iv.begin());
}