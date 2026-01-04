#pragma once
#include <mode/mode.hpp>

class CTR : public Mode {
public:
    std::string encryptBlock(const std::string& data) override;
    std::string decryptBlock(const std::string& data) override;
    ~CTR() override = default;
};