#include "crypto_pp_adapter.hpp"
#include <stdexcept>

CryptoPP_AES128_ECB_Adapter::CryptoPP_AES128_ECB_Adapter()
    : keySet_(false)
{
}

void CryptoPP_AES128_ECB_Adapter::setKey(const std::vector<uint8_t>& key) {
    if (key.size() != CryptoPP::AES::DEFAULT_KEYLENGTH) {
        throw std::runtime_error("CryptoPP_AES128_ECB_Adapter: key must be 16 bytes");
    }
    enc_.SetKey(key.data(), key.size());
    dec_.SetKey(key.data(), key.size());
    keySet_ = true;
}

void CryptoPP_AES128_ECB_Adapter::encryptBlock(const uint8_t* in, uint8_t* out) const {
    if (!keySet_) {
        throw std::runtime_error("CryptoPP_AES128_ECB_Adapter: key not set");
    }
    enc_.ProcessData(out, in, blockSize());
}

void CryptoPP_AES128_ECB_Adapter::decryptBlock(const uint8_t* in, uint8_t* out) const {
    if (!keySet_) {
        throw std::runtime_error("CryptoPP_AES128_ECB_Adapter: key not set");
    }
    dec_.ProcessData(out, in, blockSize());
}
