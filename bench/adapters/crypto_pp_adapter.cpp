#include "crypto_pp_adapter.hpp"
#include <stdexcept>

CryptoPP_AES128_ECB_Adapter::CryptoPP_AES128_ECB_Adapter()
    : keySet_(false)
{
}

size_t CryptoPP_AES128_ECB_Adapter::blockSize() const {
    return CryptoPP::AES::BLOCKSIZE;
}

void CryptoPP_AES128_ECB_Adapter::setKey(const std::vector<uint8_t>& key) {
    if (key.size() != CryptoPP::AES::DEFAULT_KEYLENGTH) {
        throw std::runtime_error("CryptoPP_AES128_ECB_Adapter: key must be 16 bytes");
    }
    enc_.SetKey(key.data(), key.size());
    keySet_ = true;
}

std::vector<uint8_t> CryptoPP_AES128_ECB_Adapter::encrypt(const std::vector<uint8_t>& pt) {
    if (!keySet_) {
        throw std::runtime_error("Key not set");
    }

    std::vector<uint8_t> out(pt.size());

    CryptoPP::ArraySource(
        pt.data(), pt.size(), true,
        new CryptoPP::StreamTransformationFilter(
            enc_,
            new CryptoPP::ArraySink(out.data(), out.size()),
            CryptoPP::StreamTransformationFilter::NO_PADDING
        )
    );
    return out;
}
