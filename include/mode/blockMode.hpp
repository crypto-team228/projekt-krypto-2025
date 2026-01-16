#pragma once
#include <vector>
#include <array>
#include "mode/mode.hpp"
#include "mode/PaddingMode.hpp"

class BlockMode : public Mode {
public:
    void setPadding(PaddingMode m) { padding = m; }

protected:
    void applyPadding(std::vector<uint8_t>& data, size_t blockSize) const;
    void removePadding(std::vector<uint8_t>& data, size_t blockSize) const;

    static void xorBlock(std::array<uint8_t, 16>& a,
        const std::array<uint8_t, 16>& b);

protected:
    PaddingMode padding = PaddingMode::PKCS7;
};
