#pragma once
#include <string>
#include <bitset>
#include <array>

class TDES
{
public:
	TDES();
	std::string encrypt(std::string plainText);
	std::string decrypt(std::string cipherText);
	std::array<uint8_t, 64> test(std::array<uint8_t,64> str);

public:
	static const std::array<std::uint8_t,64> initialPermutation;
	static const std::array<std::uint8_t,48> expansionD;
	static const std::array<std::uint8_t,32> straightPermutation;
	static const std::array<std::uint8_t,64> finalPermutation;
	static const std::array<std::array<std::array<std::uint8_t, 16>, 4>, 8> sbox;

	template <std::size_t N, std::size_t M>
	std::array<std::uint8_t, N> permute(const std::array<uint8_t, N>& table, const std::array<std::uint8_t, M>& input);
};
