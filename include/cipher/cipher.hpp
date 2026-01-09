#pragma once
#include <string>
#include <vector>

class Cipher {
public:
    virtual size_t blockSize() const = 0;
    virtual void setKey(const std::vector<uint8_t>& key) = 0;
    virtual void encryptBlock(const uint8_t* in, uint8_t* out) const = 0;
    virtual void decryptBlock(const uint8_t* in, uint8_t* out) const = 0;
    virtual ~Cipher() = default;
};