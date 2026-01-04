#pragma once
#include <mode/mode.hpp>

class CTR : public Mode {
public:
    std::string encrypt(const std::string& data) override;
    std::string decrypt(const std::string& data) override;
    ~CTR() override = default;
};