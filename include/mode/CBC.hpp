#pragma once
#include <mode/mode.hpp>

class CBC : public Mode {
public:
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data, Cipher& cipher) override;
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data, Cipher& cipher) override;
};