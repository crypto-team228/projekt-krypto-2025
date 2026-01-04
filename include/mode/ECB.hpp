#pragma once
#include <mode/mode.hpp>

class ECB : public Mode {
public:
    std::string encryptBlock(const std::string& data) override;
    std::string decryptBlock(const std::string& data) override;
    ~ECB() override = default;
};