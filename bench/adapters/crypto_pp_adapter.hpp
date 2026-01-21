#pragma once
#include "cipher/cipher.hpp"
#include <aes.h>
#include <modes.h>

class CryptoPP_AES128_ECB_Adapter : public Cipher {
public:
    CryptoPP_AES128_ECB_Adapter();

    size_t blockSize() const override { return CryptoPP::AES::BLOCKSIZE; }
    size_t batchSize() const override { return 1; }

    void setKey(const std::vector<uint8_t>& key) override;

    void encryptBlock(const uint8_t* in, uint8_t* out) const override;
    void decryptBlock(const uint8_t* in, uint8_t* out) const override;

    std::string sourceName() const { return "Crypto++ AES-128-ECB"; }

private:
    mutable CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption enc_;
    mutable CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption dec_;
    bool keySet_;
};
