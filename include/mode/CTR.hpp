#pragma once
#include <array>
#include <mode/mode.hpp>

class CTR : public Mode {
public:
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data, Cipher& cipher) override;
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data, Cipher& cipher) override;
    void setIV(const std::vector<uint8_t>& iv);
    std::array<uint8_t, 16> iv = { 0 };
};