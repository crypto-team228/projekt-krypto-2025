#pragma once
#pragma message("cipher.hpp LOADED FROM: " __FILE__)

#include "cipher/cipher.hpp"
#include <aes.h>
#include <modes.h>
#include <vector>
#include <string>
#include <des.h>

class CryptoPP_AES_ECB_Adapter : public Cipher {
public:
    CryptoPP_AES_ECB_Adapter();
    ~CryptoPP_AES_ECB_Adapter() override = default;

    size_t blockSize() const override { return CryptoPP::AES::BLOCKSIZE; }
    size_t batchSize() const override { return 1; }

    void setKey(const std::vector<uint8_t>& key) override;

    void encryptBlock(const uint8_t* in, uint8_t* out) const override;
    void decryptBlock(const uint8_t* in, uint8_t* out) const override;

    std::string sourceName() const;

private:
    mutable CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption enc_;
    mutable CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption dec_;
    size_t keySizeBytes_;
    bool keySet_;
};


class CryptoPP_3DES_ECB_Adapter : public Cipher {
public:
    CryptoPP_3DES_ECB_Adapter();
    ~CryptoPP_3DES_ECB_Adapter() override = default;

    size_t blockSize() const override { return CryptoPP::DES_EDE3::BLOCKSIZE; } // 8
    size_t batchSize() const override { return 1; }

    void setKey(const std::vector<uint8_t>& key) override;

    void encryptBlock(const uint8_t* in, uint8_t* out) const override;
    void decryptBlock(const uint8_t* in, uint8_t* out) const override;

    std::string sourceName() const;

private:
    mutable CryptoPP::ECB_Mode<CryptoPP::DES_EDE3>::Encryption enc_;
    mutable CryptoPP::ECB_Mode<CryptoPP::DES_EDE3>::Decryption dec_;
    size_t keySizeBytes_;
    bool keySet_;
};
