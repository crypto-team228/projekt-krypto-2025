#include "crypto_pp_adapter.hpp"
#include <stdexcept>

CryptoPP_AES_ECB_Adapter::CryptoPP_AES_ECB_Adapter()
    : keySizeBytes_(0), keySet_(false)
{
}

void CryptoPP_AES_ECB_Adapter::setKey(const std::vector<uint8_t>& key) {
    if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
        throw std::runtime_error("CryptoPP_AES_ECB_Adapter: key must be 16, 24 or 32 bytes");
    }

    enc_.SetKey(key.data(), key.size());
    dec_.SetKey(key.data(), key.size());
    keySizeBytes_ = key.size();
    keySet_ = true;
}

void CryptoPP_AES_ECB_Adapter::encryptBlock(const uint8_t* in, uint8_t* out) const {
    if (!keySet_) {
        throw std::runtime_error("CryptoPP_AES_ECB_Adapter: key not set");
    }
    enc_.ProcessData(out, in, blockSize());
}

void CryptoPP_AES_ECB_Adapter::decryptBlock(const uint8_t* in, uint8_t* out) const {
    if (!keySet_) {
        throw std::runtime_error("CryptoPP_AES_ECB_Adapter: key not set");
    }
    dec_.ProcessData(out, in, blockSize());
}

std::string CryptoPP_AES_ECB_Adapter::sourceName() const {
    switch (keySizeBytes_) {
    case 16: return "Crypto++ AES-128-ECB";
    case 24: return "Crypto++ AES-192-ECB";
    case 32: return "Crypto++ AES-256-ECB";
    default: return "Crypto++ AES-ECB (no key)";
    }
}


// 3DES ECB Adapter implementation ---------------------------------

CryptoPP_3DES_ECB_Adapter::CryptoPP_3DES_ECB_Adapter()
    : keySizeBytes_(0), keySet_(false)
{
}

void CryptoPP_3DES_ECB_Adapter::setKey(const std::vector<uint8_t>& key) {
    // CryptoPP DES_EDE3 akceptuje 16 (2-key) lub 24 (3-key)
    if (key.size() != 16 && key.size() != 24) {
        throw std::runtime_error("CryptoPP_3DES_ECB_Adapter: key must be 16 or 24 bytes");
    }

    enc_.SetKey(key.data(), key.size());
    dec_.SetKey(key.data(), key.size());
    keySizeBytes_ = key.size();
    keySet_ = true;
}

void CryptoPP_3DES_ECB_Adapter::encryptBlock(const uint8_t* in, uint8_t* out) const {
    if (!keySet_) {
        throw std::runtime_error("CryptoPP_3DES_ECB_Adapter: key not set");
    }
    enc_.ProcessData(out, in, blockSize());
}

void CryptoPP_3DES_ECB_Adapter::decryptBlock(const uint8_t* in, uint8_t* out) const {
    if (!keySet_) {
        throw std::runtime_error("CryptoPP_3DES_ECB_Adapter: key not set");
    }
    dec_.ProcessData(out, in, blockSize());
}

std::string CryptoPP_3DES_ECB_Adapter::sourceName() const {
    switch (keySizeBytes_) {
    case 16: return "Crypto++ 2-key 3DES-ECB";
    case 24: return "Crypto++ 3-key 3DES-ECB";
    default: return "Crypto++ 3DES-ECB (no key)";
    }
}
