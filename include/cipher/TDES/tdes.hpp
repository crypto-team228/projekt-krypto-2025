#pragma once
#include <cstdint>
#include <string>
#include <bitset>
#include <array>
#include <iostream>
#include <algorithm>
#include <cipher/cipher.hpp>

class TDES : public Cipher
{
public:
	TDES();
	std::string encryptBlock(const std::string& data, std::string key) override;
	std::string decryptBlock(const std::string& data, std::string key) override;
	std::array<uint8_t, 64> Test(std::array<uint8_t,64> str);

	std::string EncryptBlock(std::string plainText, std::string key1, std::string key2, std::string key3);
	std::string EncryptBlock(std::string plainText, std::string key1, std::string key2);

	std::string DecryptBlock(std::string cipherText, std::string key1, std::string key2, std::string key3);
	std::string DecryptBlock(std::string cipherText, std::string key1, std::string key2);

	template <std::size_t N>
	std::array<uint8_t, N> HexStringToBitArray(const std::string &hexStr);
	template <std::size_t N>
	std::string BitArrayToHexString(const std::array<uint8_t, N> &bits);
	template <std::size_t N>
	std::array<uint8_t, N> StringToBitArray(const std::string &str);
	template <std::size_t N>
	std::string BitArrayToString(const std::array<uint8_t, N> &bits);

private:
	std::string OneKeyEncryptBlock(std::string plainText, std::string key);
	std::string OneKeyDecryptBlock(std::string cipherText, std::string key);

	static const std::array<std::uint8_t, 64> initialPermutation;
	static const std::array<std::uint8_t, 48> expansionD;
	static const std::array<std::uint8_t, 32> straightPermutation;
	static const std::array<std::uint8_t, 64> finalPermutation;
	static const std::array<std::array<std::array<std::uint8_t, 16>, 4>, 8> sbox;
	
	static const std::array<std::uint8_t, 56> parityBitDropTable;
	static const std::array<uint8_t, 28> keyShiftTable;
	static const std::array<uint8_t, 48> keyCompressionTable;

	std::array<uint8_t, 32> FeistelFunction(std::array<uint8_t, 32> right, std::array<uint8_t, 48> subkey);

	template <std::size_t N, std::size_t M>
	std::array<std::uint8_t, N> Permute(const std::array<uint8_t, N> &table, const std::array<std::uint8_t, M> &input);
	std::array<std::array<uint8_t, 48>, 16> GenerateSubkeys(std::array<uint8_t, 64> key);
	std::array<uint8_t, 28> ShiftLeft(std::array<uint8_t, 28> halfKey, int shifts);

	std::array<uint8_t, 64> DESEncryptBlock(std::array<uint8_t, 64> block, std::array<std::array<uint8_t, 48>, 16> subkeys);
	std::array<uint8_t, 64> DESDecryptBlock(std::array<uint8_t, 64> block, std::array<std::array<uint8_t, 48>, 16> subkeys);


};
