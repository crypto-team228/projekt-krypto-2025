#pragma once
#include <memory>
#include <string>
#include <cipher/cipher.hpp>

class CipherFactory {
public:
    static std::unique_ptr<Cipher> create(const std::string& name);
};
