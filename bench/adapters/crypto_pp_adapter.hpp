#pragma once
#include "cipher_adapter.hpp"
#include <aes.h>
#include <modes.h>
#include <filters.h>

class CryptoPP_AES128_ECB_Adapter : public CipherAdapter {
public:
    CryptoPP_AES128_ECB_Adapter();

    size_t blockSize() const override;
    void setKey(const std::vector<uint8_t>& key) override;
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& pt) override;
    std::string sourceName() const override { return "Crypto++"; }

private:
    CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption enc_;
    bool keySet_;
};
