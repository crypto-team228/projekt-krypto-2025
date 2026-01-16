#pragma once
#include <array>
#include <mode/mode.hpp>
#include <mode/blockMode.hpp>

class CTR : public BlockMode {
public:
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data, Cipher& cipher) override;
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data, Cipher& cipher) override;
    void setIV(const std::vector<uint8_t>& iv);
private:
    void incCounter(std::array<uint8_t, 16>& counter) const;
    std::array<uint8_t, 16> iv = {};
};