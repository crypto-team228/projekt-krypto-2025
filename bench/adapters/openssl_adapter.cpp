#include "openssl_adapter.hpp"
#include <stdexcept>

OpenSSL_AES128_ECB_Adapter::OpenSSL_AES128_ECB_Adapter()
    : ctx_(EVP_CIPHER_CTX_new())
{
    if (!ctx_) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }
}

OpenSSL_AES128_ECB_Adapter::~OpenSSL_AES128_ECB_Adapter() {
    if (ctx_) {
        EVP_CIPHER_CTX_free(ctx_);
    }
}

size_t OpenSSL_AES128_ECB_Adapter::blockSize() const {
    return EVP_CIPHER_block_size(EVP_aes_128_ecb());
}

void OpenSSL_AES128_ECB_Adapter::setKey(const std::vector<uint8_t>& key) {
    if (key.size() != 16) {
        throw std::runtime_error("OpenSSL_AES128_ECB_Adapter: key must be 16 bytes");
    }
    key_ = key;
}

std::vector<uint8_t> OpenSSL_AES128_ECB_Adapter::encrypt(const std::vector<uint8_t>& pt) {
    if (key_.empty()) {
        throw std::runtime_error("Key not set");
    }

    std::vector<uint8_t> out(pt.size() + blockSize());
    int outlen1 = 0, outlen2 = 0;

    if (EVP_EncryptInit_ex(ctx_, EVP_aes_128_ecb(), nullptr, key_.data(), nullptr) != 1) {
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }

    if (EVP_EncryptUpdate(ctx_, out.data(), &outlen1, pt.data(), static_cast<int>(pt.size())) != 1) {
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }

    if (EVP_EncryptFinal_ex(ctx_, out.data() + outlen1, &outlen2) != 1) {
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }

    out.resize(outlen1 + outlen2);
    return out;
}
