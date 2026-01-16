#include "mode/ECB.hpp"
#include <stdexcept>

std::vector<uint8_t> ECB::encrypt(const std::vector<uint8_t>& data, Cipher& cipher)
{
    std::vector<uint8_t> out = data;
    const size_t blockSize = cipher.blockSize();
    applyPadding(out, blockSize);

    for (size_t i = 0; i < out.size(); i += blockSize)
        cipher.encryptBlock(&out[i], &out[i]);

    return out;
}

std::vector<uint8_t> ECB::decrypt(const std::vector<uint8_t>& data, Cipher& cipher)
{
    const size_t blockSize = cipher.blockSize();
    if (data.size() % blockSize != 0)
        throw std::runtime_error("ECB decrypt: invalid ciphertext size");

    std::vector<uint8_t> out = data;

    for (size_t i = 0; i < out.size(); i += blockSize)
        cipher.decryptBlock(&out[i], &out[i]);

    removePadding(out, blockSize);
    return out;
}
