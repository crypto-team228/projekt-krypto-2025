#pragma once
#include <vector>
#include "cipher/cipher.hpp"

class Mode {
public:

	virtual std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data, Cipher& cipher) = 0;

	virtual std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data, Cipher& cipher) = 0;
};