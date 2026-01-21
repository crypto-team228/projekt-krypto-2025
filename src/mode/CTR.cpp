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
    const size_t B = cipher.blockSize();
    const size_t N = cipher.batchSize();

    std::vector<uint8_t> out(data.size());

    std::array<uint8_t, 16> counter = iv;

    size_t blocks = (data.size() + B - 1) / B;
    size_t i = 0;

    while (i < blocks) {
        size_t chunk = std::min(N, blocks - i);

        // przygotuj chunk counterow
        std::vector<uint8_t> ctrBuf(chunk * B);
        for (size_t j = 0; j < chunk; j++) {
            std::copy(counter.begin(), counter.begin() + B, &ctrBuf[j * B]);
            incCounter(counter);
        }

        // szyfrujemy countery -> keystream
        cipher.encryptBlocks(ctrBuf.data(), ctrBuf.data(), chunk);

        // XOR z plaintextem
        for (size_t j = 0; j < chunk; j++) {
            size_t offset = (i + j) * B;
            size_t len = std::min(B, data.size() - offset);

            for (size_t k = 0; k < len; k++)
                out[offset + k] = data[offset + k] ^ ctrBuf[j * B + k];
        }

        i += chunk;
    }

    return out;
}

std::vector<uint8_t> CTR::decrypt(const std::vector<uint8_t>& data, Cipher& cipher)
{
    return encrypt(data, cipher);
}
