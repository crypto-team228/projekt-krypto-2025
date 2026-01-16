#pragma once
#include <mode/mode.hpp>
#include <mode/blockMode.hpp>

class ECB : public BlockMode {
public:
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data, Cipher& cipher) override;
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data, Cipher& cipher) override;
};