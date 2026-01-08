#pragma once
#include <cstdint>
#include <string>
#include <bitset>
#include <array>
#include <iostream>
#include <algorithm>
#include <cipher/cipher.hpp>
#include "utils/DataConverter.hpp"

class TDES : public Cipher
{
public:
	TDES();
	TDES(const std::vector<uint8_t>& key);
	void encryptBlock(const uint8_t* in, uint8_t* out) const override;
	void decryptBlock(const uint8_t* in, uint8_t* out) const override;
	void setKey(const std::vector<uint8_t>& key) override;
	static constexpr size_t BLOCK_SIZE = 8;
	size_t blockSize() const override;

private:
	using Bit64 = std::array<uint8_t, 64>;
	using Bit56 = std::array<uint8_t, 56>;
	using Bit48 = std::array<uint8_t, 48>;
	using Bit32 = std::array<uint8_t, 32>;
	using Bit28 = std::array<uint8_t, 28>;
	using Subkey = Bit48;
	using SubkeySchedule = std::array<Subkey, 16>;

	static const Bit64 initialPermutation;
	static const Bit48 expansionD;
	static const Bit32 straightPermutation;
	static const Bit64 finalPermutation;
	static const std::array<std::array<std::array<std::uint8_t, 16>, 4>, 8> sbox;
	
	static const Bit56 parityBitDropTable;
	static const Bit28 keyShiftTable;
	static const Bit48 keyCompressionTable;

	Bit32 FeistelFunction(const Bit32& right, const Bit48& subkey) const;

	template<std::size_t N, typename Input> 
	static std::array<uint8_t, N> Permute(const std::array<uint8_t, N>& table, const Input& input)
	{
		std::array<uint8_t, N> result{};
		for (std::size_t i = 0; i < N; i++)
		{
			// jeœli tabele s¹ 1-based, u¿yj table[i] - 1 
			std::size_t idx = static_cast<std::size_t>(table[i]);
			result[i] = input[idx];
		}
		return result;
	}
	std::array<std::array<uint8_t, 48>, 16> GenerateSubkeys(const std::vector<uint8_t>& key);
	Bit28 ShiftLeft(const Bit28& halfKey, int shifts) const;

	Bit64 DESEncryptBlock(const Bit64& block, const SubkeySchedule& subkeys) const;
	Bit64 DESDecryptBlock(const Bit64& block, const SubkeySchedule& subkeys) const;

	// 3DES (EDE) – na bitach 
	Bit64 TripleDESEncrypt(const Bit64& bits) const;
	Bit64 TripleDESDecrypt(const Bit64& bits) const;


	SubkeySchedule subkeys1{};
	SubkeySchedule subkeys2{}; 
	SubkeySchedule subkeys3{};

};
