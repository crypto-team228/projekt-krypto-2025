#pragma once
#include <array>
#include <mode/mode.hpp>
#include <mode/blockMode.hpp>

class CBC : public BlockMode {
public:
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data, Cipher& cipher) override;
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data, Cipher& cipher) override;
    void setIV(const std::vector<uint8_t>& iv);

private:
    std::array<uint8_t, 16> iv = {};
};