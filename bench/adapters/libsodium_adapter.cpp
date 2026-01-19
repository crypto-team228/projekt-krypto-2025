#include "libsodium_adapter.hpp"
#include <stdexcept>

Libsodium_AES256_GCM_Adapter::Libsodium_AES256_GCM_Adapter() {
    if (sodium_init() < 0) {
        throw std::runtime_error("sodium_init failed");
    }
    if (!crypto_aead_aes256gcm_is_available()) {
        throw std::runtime_error("AES256-GCM not available on this CPU");
    }
}

size_t Libsodium_AES256_GCM_Adapter::blockSize() const {
    // Nie ma klasycznego "block size", ale mo¿esz przyj¹æ 16 dla AES
    return 16;
}

void Libsodium_AES256_GCM_Adapter::setKey(const std::vector<uint8_t>& key) {
    if (key.size() != crypto_aead_aes256gcm_KEYBYTES) {
        throw std::runtime_error("Libsodium_AES256_GCM_Adapter: key must be 32 bytes");
    }
    key_ = key;
}

std::vector<uint8_t> Libsodium_AES256_GCM_Adapter::encrypt(const std::vector<uint8_t>& pt) {
    if (key_.empty()) {
        throw std::runtime_error("Key not set");
    }

    std::vector<uint8_t> nonce(crypto_aead_aes256gcm_NPUBBYTES, 0x42); // sta³y nonce do benchmarku
    std::vector<uint8_t> ct(pt.size() + crypto_aead_aes256gcm_ABYTES);

    unsigned long long clen = 0;
    if (crypto_aead_aes256gcm_encrypt(
        ct.data(), &clen,
        pt.data(), pt.size(),
        nullptr, 0,          // brak AAD
        nullptr,
        nonce.data(),
        key_.data()) != 0) {
        throw std::runtime_error("crypto_aead_aes256gcm_encrypt failed");
    }

    ct.resize(static_cast<size_t>(clen));
    return ct;
}
