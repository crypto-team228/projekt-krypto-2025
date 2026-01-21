#include "openssl_adapter.hpp"
#include <stdexcept>

void OpenSSL_AES128_ECB_Adapter::setKey(const std::vector<uint8_t>& key) {
    if (key.size() != 16) {
        throw std::runtime_error("OpenSSL_AES128_ECB_Adapter: key must be 16 bytes");
    }
    key_ = key;
}

void OpenSSL_AES128_ECB_Adapter::encryptBlock(const uint8_t* in, uint8_t* out) const {
    if (key_.empty()) {
        throw std::runtime_error("OpenSSL_AES128_ECB_Adapter: key not set");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    int outlen1 = 0, outlen2 = 0;
    unsigned char buf[32]; // 16 + max padding, ale u¿ywamy bez paddingu

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key_.data(), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (EVP_EncryptUpdate(ctx, buf, &outlen1, in, 16) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }

    if (EVP_EncryptFinal_ex(ctx, buf + outlen1, &outlen2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }

    EVP_CIPHER_CTX_free(ctx);

    if (outlen1 + outlen2 != 16) {
        throw std::runtime_error("OpenSSL_AES128_ECB_Adapter: unexpected output length");
    }

    std::copy(buf, buf + 16, out);
}

void OpenSSL_AES128_ECB_Adapter::decryptBlock(const uint8_t* in, uint8_t* out) const {
    if (key_.empty()) {
        throw std::runtime_error("OpenSSL_AES128_ECB_Adapter: key not set");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    int outlen1 = 0, outlen2 = 0;
    unsigned char buf[32];

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key_.data(), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (EVP_DecryptUpdate(ctx, buf, &outlen1, in, 16) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }

    if (EVP_DecryptFinal_ex(ctx, buf + outlen1, &outlen2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptFinal_ex failed");
    }

    EVP_CIPHER_CTX_free(ctx);

    if (outlen1 + outlen2 != 16) {
        throw std::runtime_error("OpenSSL_AES128_ECB_Adapter: unexpected output length");
    }

    std::copy(buf, buf + 16, out);
}
