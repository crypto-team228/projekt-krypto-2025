#pragma once
#include <mode/mode.hpp>

class ECB : public Mode {
public:
    std::string encrypt(const std::string& data) override;
    std::string decrypt(const std::string& data) override;
    ~ECB() override = default;
};