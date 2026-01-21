#include "mode/ECB.hpp"
#include <stdexcept>
#include <iostream>

std::vector<uint8_t> ECB::encrypt(const std::vector<uint8_t>& data, Cipher& cipher)
{
    std::vector<uint8_t> out = data;
    const size_t B = cipher.blockSize();
    const size_t N = cipher.batchSize();

    applyPadding(out, B);

    size_t blocks = out.size() / B;
    size_t i = 0;

    while (i < blocks) {
        size_t chunk = std::min(N, blocks - i);
        cipher.encryptBlocks(&out[i * B], &out[i * B], chunk);
        i += chunk;
    }

    return out;
}

std::vector<uint8_t> ECB::decrypt(const std::vector<uint8_t>& data, Cipher& cipher)
{
    const size_t B = cipher.blockSize();
    const size_t N = cipher.batchSize();

    if (data.size() % B != 0)
        throw std::runtime_error("ECB decrypt: invalid ciphertext size");

    std::vector<uint8_t> out = data;
    size_t blocks = out.size() / B;
    size_t i = 0;

    while (i < blocks) {
        size_t chunk = std::min(N, blocks - i);
        cipher.decryptBlocks(&out[i * B], &out[i * B], chunk);
        i += chunk;
    }

    removePadding(out, B);
    return out;
}

