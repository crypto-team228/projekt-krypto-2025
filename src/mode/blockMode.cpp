#include "mode/BlockMode.hpp"
#include <stdexcept>

void BlockMode::applyPadding(std::vector<uint8_t>& data, size_t blockSize) const
{
    if (padding == PaddingMode::PKCS7) {
        size_t pad = blockSize - (data.size() % blockSize);
        if (pad == 0) pad = blockSize;
        data.insert(data.end(), pad, static_cast<uint8_t>(pad));
    }
    else if (padding == PaddingMode::ZeroPadding) {
        size_t pad = (blockSize - (data.size() % blockSize)) % blockSize;
        data.insert(data.end(), pad, 0x00);
    }
    else if (padding == PaddingMode::None) {
        if (data.size() % blockSize != 0)
            throw std::runtime_error("Padding NONE but data not aligned");
    }
}

void BlockMode::removePadding(std::vector<uint8_t>& data, size_t blockSize) const
{
    if (padding == PaddingMode::PKCS7) {
        if (data.empty())
            throw std::runtime_error("Invalid PKCS7 padding (empty)");
        uint8_t pad = data.back();
        if (pad == 0 || pad > blockSize || pad > data.size())
            throw std::runtime_error("Invalid PKCS7 padding");
        data.resize(data.size() - pad);
    }
    else if (padding == PaddingMode::ZeroPadding) {
        while (!data.empty() && data.back() == 0)
            data.pop_back();
    }
}

void BlockMode::xorBlock(std::array<uint8_t, 16>& a,
    const std::array<uint8_t, 16>& b)
{
    for (int i = 0; i < 16; ++i)
        a[i] ^= b[i];
}
