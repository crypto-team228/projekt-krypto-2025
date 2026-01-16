#include "mode/CTR.hpp"
#include <algorithm>
#include <stdexcept>

void CTR::setIV(const std::vector<uint8_t>& initVector)
{
    if (initVector.size() != 16)
        throw std::invalid_argument("IV must be 16 bytes");
    std::copy(initVector.begin(), initVector.end(), iv.begin());
}

void CTR::incCounter(std::array<uint8_t, 16>& counter) const
{
    for (int i = 15; i >= 0; --i) {
        uint16_t v = static_cast<uint16_t>(counter[i]) + 1;
        counter[i] = static_cast<uint8_t>(v & 0xFF);
        if (!(v & 0x100)) break;
    }
}

std::vector<uint8_t> CTR::encrypt(const std::vector<uint8_t>& data, Cipher& cipher)
{
    const size_t blockSize = cipher.blockSize();
    std::vector<uint8_t> out(data.size());

    std::array<uint8_t, 16> counter = iv;
    std::array<uint8_t, 16> keystream{};

    size_t numBlocks = (data.size() + blockSize - 1) / blockSize;

    for (size_t i = 0; i < numBlocks; ++i) {
        cipher.encryptBlock(counter.data(), keystream.data());

        size_t offset = i * blockSize;
        size_t len = std::min(blockSize, data.size() - offset);

        for (size_t j = 0; j < len; ++j)
            out[offset + j] = static_cast<uint8_t>(data[offset + j] ^ keystream[j]);

        incCounter(counter);
    }

    return out;
}

std::vector<uint8_t> CTR::decrypt(const std::vector<uint8_t>& data, Cipher& cipher)
{
    // CTR: decrypt == encrypt
    return encrypt(data, cipher);
}
