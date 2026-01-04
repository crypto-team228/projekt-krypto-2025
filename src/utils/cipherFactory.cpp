#include <unordered_map>
#include <functional>
#include <memory>
#include <string>
#include <stdexcept>
#include <iostream>

#include <cipher/cipher.hpp>
#include <core/cipherFactory.hpp>
#include <cipher/AES/AES.hpp>
#include <cipher/TDES/TDES.hpp>

using FactoryFn = std::function<std::unique_ptr<Cipher>()>;

static const std::unordered_map<std::string, FactoryFn> getRegistry = {
    {"AES", []() -> std::unique_ptr<Cipher> { return std::make_unique<AES>(); }},
    {"TDES", []() -> std::unique_ptr<Cipher> { return std::make_unique<TDES>(); }}
};
