//#pragma once
//#include "cipher_adapter.hpp"
//#include <sodium.h>
//
//class Libsodium_AES256_GCM_Adapter : public CipherAdapter {
//public:
//    Libsodium_AES256_GCM_Adapter();
//
//    size_t blockSize() const override;
//    void setKey(const std::vector<uint8_t>& key) override;
//    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& pt) override;
//    std::string sourceName() const override { return "libsodium"; }
//
//private:
//    std::vector<uint8_t> key_;
//};
