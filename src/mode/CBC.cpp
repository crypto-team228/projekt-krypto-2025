#include "mode/CBC.hpp"
#include <algorithm>
#include <stdexcept>

void CBC::setIV(const std::vector<uint8_t>& initVector)
{
    if (initVector.size() != 16)
        throw std::invalid_argument("IV must be 16 bytes");
    std::copy(initVector.begin(), initVector.end(), iv.begin());
}

std::vector<uint8_t> CBC::encrypt(const std::vector<uint8_t>& data, Cipher& cipher)
{
    std::vector<uint8_t> out = data;
    const size_t blockSize = cipher.blockSize();
    applyPadding(out, blockSize);

    std::array<uint8_t, 16> prev = iv;
    std::array<uint8_t, 16> block{};

    for (size_t i = 0; i < out.size(); i += blockSize) {
        std::copy(out.begin() + i, out.begin() + i + blockSize, block.begin());
        xorBlock(block, prev);
        cipher.encryptBlock(block.data(), block.data());
        std::copy(block.begin(), block.end(), out.begin() + i);
        prev = block;
    }

    return out;
}

std::vector<uint8_t> CBC::decrypt(const std::vector<uint8_t>& data, Cipher& cipher)
{
    const size_t blockSize = cipher.blockSize();
    if (data.size() % blockSize != 0)
        throw std::runtime_error("CBC decrypt: invalid ciphertext size");

    std::vector<uint8_t> out = data;

    std::array<uint8_t, 16> prev = iv;
    std::array<uint8_t, 16> block{};
    std::array<uint8_t, 16> decrypted{};

    for (size_t i = 0; i < out.size(); i += blockSize) {
        std::copy(out.begin() + i, out.begin() + i + blockSize, block.begin());
        cipher.decryptBlock(block.data(), decrypted.data());
        xorBlock(decrypted, prev);
        std::copy(decrypted.begin(), decrypted.end(), out.begin() + i);
        prev = block;
    }

    removePadding(out, blockSize);
    return out;
}
