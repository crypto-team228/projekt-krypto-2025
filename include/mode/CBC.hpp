#pragma once
#include <mode/mode.hpp>

class CBC : public Mode {
public:
    std::string encryptBlock(const std::string& data) override;
    std::string decryptBlock(const std::string& data) override;
    ~CBC() override = default;
};