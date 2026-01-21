#pragma once
#include "cipher/cipher.hpp"
#include <openssl/evp.h>
#include <vector>
#include <string>

class OpenSSL_AES128_ECB_Adapter : public Cipher {
public:
    OpenSSL_AES128_ECB_Adapter() = default;
    ~OpenSSL_AES128_ECB_Adapter() override = default;

    size_t blockSize() const override { return 16; }
    size_t batchSize() const override { return 1; }

    void setKey(const std::vector<uint8_t>& key) override;

    void encryptBlock(const uint8_t* in, uint8_t* out) const override;
    void decryptBlock(const uint8_t* in, uint8_t* out) const override;

    std::string sourceName() const { return "OpenSSL AES-128-ECB"; }

private:
    std::vector<uint8_t> key_;
};
