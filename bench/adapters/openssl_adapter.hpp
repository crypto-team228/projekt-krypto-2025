#pragma once
#include "cipher/cipher.hpp"
#include <openssl/evp.h>
#include <vector>
#include <string>
#include <stdexcept>

class OpenSSL_AES_ECB_Adapter : public Cipher {
public:
    OpenSSL_AES_ECB_Adapter() = default;
    ~OpenSSL_AES_ECB_Adapter() override = default;

    size_t blockSize() const override { return 16; }
    size_t batchSize() const override { return 1; }

    void setKey(const std::vector<uint8_t>& key) override;

    void encryptBlock(const uint8_t* in, uint8_t* out) const override;
    void decryptBlock(const uint8_t* in, uint8_t* out) const override;

    std::string sourceName() const;

private:
    const EVP_CIPHER* selectCipher() const;

    size_t keySizeBytes_ = 0;        // 16, 24, 32
    std::vector<uint8_t> key_;
};


class OpenSSL_3DES_ECB_Adapter : public Cipher {
public:
    OpenSSL_3DES_ECB_Adapter() = default;
    ~OpenSSL_3DES_ECB_Adapter() override = default;

    size_t blockSize() const override { return 8; }
    size_t batchSize() const override { return 1; }

    void setKey(const std::vector<uint8_t>& key) override;

    void encryptBlock(const uint8_t* in, uint8_t* out) const override;
    void decryptBlock(const uint8_t* in, uint8_t* out) const override;

    std::string sourceName() const;

private:
    const EVP_CIPHER* selectCipher() const;

    std::vector<uint8_t> key_;
    size_t keySizeBytes_ = 0; // 16 (2-key 3DES) lub 24 (3-key 3DES)
};
