#pragma once
#include <string>

class Cipher {
public:
	virtual ~Cipher() = default;

	virtual std::string encryptBlock(const std::string& data, std::string key) = 0;

	virtual std::string decryptBlock(const std::string& data, std::string key) = 0;
};