#pragma once
#include "cipher_adapter.hpp"
#include <openssl/evp.h>

class OpenSSL_AES128_ECB_Adapter : public CipherAdapter {
public:
    OpenSSL_AES128_ECB_Adapter();
    ~OpenSSL_AES128_ECB_Adapter() override;

    size_t blockSize() const override;
    void setKey(const std::vector<uint8_t>& key) override;
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& pt) override;
    std::string sourceName() const override { return "OpenSSL"; }

private:
    EVP_CIPHER_CTX* ctx_;
    std::vector<uint8_t> key_;
};
