#pragma once
#include <string>

class Mode {
public:
	virtual ~Mode() = default;

	virtual std::string encrypt(const std::string& data) = 0;

	virtual std::string decrypt(const std::string& data) = 0;
};