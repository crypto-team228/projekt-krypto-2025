#pragma once
#include <vector>
#include <string>
#include <cstdint>

class CipherAdapter {
public:
    virtual ~CipherAdapter() = default;
    virtual size_t blockSize() const = 0;
    virtual void setKey(const std::vector<uint8_t>& key) = 0;
    virtual std::vector<uint8_t> encrypt(const std::vector<uint8_t>& pt) = 0;
    virtual std::string sourceName() const = 0;
};
