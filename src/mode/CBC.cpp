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
    const size_t B = cipher.blockSize();
    const size_t N = cipher.batchSize();

    applyPadding(out, B);

    std::array<uint8_t, 16> prev{};
    std::copy(iv.begin(), iv.begin() + B, prev.begin());

    size_t blocks = out.size() / B;
    size_t i = 0;

    while (i < blocks) {
        size_t chunk = std::min(N, blocks - i);

        // XOR z poprzednimi blokami
        for (size_t j = 0; j < chunk; j++) {
            uint8_t* blk = &out[(i + j) * B];
            xorBlock(blk, (j == 0 ? prev.data() : blk - B), B);
        }

        cipher.encryptBlocks(&out[i * B], &out[i * B], chunk);

        // aktualizujemy prev
        std::copy(&out[(i + chunk - 1) * B],
            &out[(i + chunk - 1) * B] + B,
            prev.begin());

        i += chunk;
    }

    return out;
}

std::vector<uint8_t> CBC::decrypt(const std::vector<uint8_t>& data, Cipher& cipher)
{
    const size_t B = cipher.blockSize();
    const size_t N = cipher.batchSize();

    if (data.size() % B != 0)
        throw std::runtime_error("CBC decrypt: invalid ciphertext size");

    std::vector<uint8_t> out = data;

    std::array<uint8_t, 16> prev{};
    std::copy(iv.begin(), iv.begin() + B, prev.begin());

    size_t blocks = out.size() / B;
    size_t i = 0;

    while (i < blocks) {
        size_t chunk = std::min(N, blocks - i);

        // kopiujemy ciphertext chunk do bufora
        std::vector<uint8_t> tmp(chunk * B);
        std::copy(&out[i * B], &out[(i + chunk) * B], tmp.begin());

        cipher.decryptBlocks(&out[i * B], &out[i * B], chunk);

        // XOR z poprzednimi blokami
        for (size_t j = 0; j < chunk; j++) {
            uint8_t* blk = &out[(i + j) * B];
            const uint8_t* prevBlk = (j == 0 ? prev.data() : &tmp[(j - 1) * B]);
            xorBlock(blk, prevBlk, B);
        }

        // aktualizujemy prev
        std::copy(&tmp[(chunk - 1) * B],
            &tmp[(chunk - 1) * B] + B,
            prev.begin());

        i += chunk;
    }

    removePadding(out, B);
    return out;
}

