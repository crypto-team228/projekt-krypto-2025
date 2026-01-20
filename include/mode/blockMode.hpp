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

    static void xorBlock(uint8_t* a, const uint8_t* b, size_t n);

protected:
    PaddingMode padding = PaddingMode::PKCS7;
};
