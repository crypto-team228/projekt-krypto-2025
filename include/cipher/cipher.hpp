#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <iostream>
class Cipher {
public:
    virtual ~Cipher() = default;
    virtual size_t blockSize() const = 0;
    virtual size_t batchSize() const { return 1; }

    virtual void setKey(const std::vector<uint8_t>& key) = 0;
    virtual void encryptBlock(const uint8_t* in, uint8_t* out) const = 0;
    virtual void decryptBlock(const uint8_t* in, uint8_t* out) const = 0;


    // (opcjonalne, domyœlnie fallback do encryptBlock)
    virtual void encryptBlocks(const uint8_t* in, uint8_t* out, size_t blocks) const {

        for (size_t i = 0; i < blocks; i++)
            encryptBlock(in + i * blockSize(), out + i * blockSize());
    }

    virtual void decryptBlocks(const uint8_t* in, uint8_t* out, size_t blocks) const {
        for (size_t i = 0; i < blocks; i++)
            decryptBlock(in + i * blockSize(), out + i * blockSize());
    }


protected:
    inline void secure_memzero(void* ptr, std::size_t len) noexcept
    {
        volatile std::uint8_t* p = static_cast<volatile std::uint8_t*>(ptr);
        while (len--) {
            *p++ = 0;
        }
    }

};