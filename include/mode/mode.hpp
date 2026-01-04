#pragma once
#include <string>

class Mode {
public:
	virtual ~Mode() = default;

	virtual std::string encryptBlock(const std::string& data) = 0;

	virtual std::string decryptBlock(const std::string& data) = 0;
};