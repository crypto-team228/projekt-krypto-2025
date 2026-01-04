#include "cipher/TDES/tdes.hpp"

TDES::TDES() {

}

void TDES::encryptBlock(const uint8_t* in, uint8_t* out) const {

}

void TDES::decryptBlock(const uint8_t* in, uint8_t* out) const {
	
}
void TDES::setKey(const std::vector<uint8_t>& key) {


}

std::string TDES::EncryptBlock(std::string plainText, std::string key1, std::string key2, std::string key3) {
	std::string result = OneKeyEncryptBlock(plainText, key1);
	result = OneKeyDecryptBlock(result, key2);
	result = OneKeyEncryptBlock(result, key3);
	return result;
}

std::string TDES::EncryptBlock(std::string plainText, std::string key1, std::string key2) {
	return EncryptBlock(plainText, key1, key2, key1);
}

std::string TDES::DecryptBlock(std::string cipherText, std::string key1, std::string key2, std::string key3) {
	std::string result = OneKeyDecryptBlock(cipherText, key3);
	result = OneKeyEncryptBlock(result, key2);
	result = OneKeyDecryptBlock(result, key1);
	return result;

}

std::string TDES::DecryptBlock(std::string cipherText, std::string key1, std::string key2) {
	return EncryptBlock(cipherText, key1, key2, key1);
}


std::string TDES::OneKeyEncryptBlock(std::string plainText, std::string key) {
	std::array<uint8_t, 64> bitPlainText = HexStringToBitArray<64>(plainText);
	std::array<uint8_t, 64> bitKey = HexStringToBitArray<64>(key);
	std::array<std::array<uint8_t, 48>, 16> subkeys = GenerateSubkeys(bitKey);
	std::array<uint8_t, 64> encryptedBlock = DESEncryptBlock(bitPlainText, subkeys);
	std::string cipherText = BitArrayToString(encryptedBlock);
	return cipherText;
}

std::string TDES::OneKeyDecryptBlock(std::string ciphreText, std::string key) {
	std::array<uint8_t, 64> bitCipherText = StringToBitArray<64>(ciphreText);
	std::array<uint8_t, 64> bitKey = HexStringToBitArray<64>(key);
	std::array<std::array<uint8_t, 48>, 16> subkeys = GenerateSubkeys(bitKey);
	std::reverse(subkeys.begin(), subkeys.end());
	std::array<uint8_t, 64> decryptedBlock = DESEncryptBlock(bitCipherText, subkeys);
	std::string plainText = BitArrayToHexString(decryptedBlock);
	return plainText;
}

std::array<uint8_t, 32> TDES::FeistelFunction(std::array<uint8_t,32> right, std::array<uint8_t, 48> subkey)
{
	// Expansion
	std::array<uint8_t, 48> expandedRight = Permute(expansionD, right);
	std::array<uint8_t, 48> xored{};
	// XOR with subkey
	std::transform(expandedRight.begin(), expandedRight.end(), subkey.begin(), xored.begin(),
                   [](uint8_t r, uint8_t k) { return r ^ k; });
    
	// S-box substitution
	std::array<uint8_t, 32> sboxOutput{};
	for (std::size_t i = 0; i < 8; i++) {
		uint8_t row = (xored[i * 6] << 1) | xored[i * 6 + 5];
		uint8_t col = (xored[i * 6 + 1] << 3) | (xored[i * 6 + 2] << 2) |
			(xored[i * 6 + 3] << 1) | xored[i * 6 + 4];
		uint8_t sboxValue = sbox[i][row][col];
		for (int j = 0; j < 4; j++) {
			sboxOutput[i * 4 + (3 - j)] = (sboxValue >> j) & 1;
		}
	}
	// Straight permutation
	std::array<uint8_t, 32> permutedSboxOutput = Permute(straightPermutation, sboxOutput);
	return permutedSboxOutput;
}

std::array<std::array<uint8_t, 48>, 16> TDES::GenerateSubkeys(std::array<uint8_t, 64> key) {
    std::array<std::array<uint8_t, 48>, 16> subkeys{};
	// Apply parity bit drop table
	std::array<uint8_t, 56> permutedKey = Permute(parityBitDropTable, key);
	// Split the key into two halves
	std::array<uint8_t, 28> leftHalf{};
	std::array<uint8_t, 28> rightHalf{};
	for (std::size_t i = 0; i < 28; i++) {
		leftHalf[i] = permutedKey[i];
		rightHalf[i] = permutedKey[i + 28];
	}
	// Generate 16 subkeys
	for (std::size_t round = 0; round < 16; round++) {
		leftHalf = ShiftLeft(leftHalf, keyShiftTable[round]);
		rightHalf = ShiftLeft(rightHalf, keyShiftTable[round]);
		// Combine the halves
		std::array<uint8_t, 56> combinedKey{};
		for (std::size_t i = 0; i < 28; i++) {
			combinedKey[i] = leftHalf[i];
			combinedKey[i + 28] = rightHalf[i];
		}
		// Apply key compression table to get the subkey
		subkeys[round] = Permute(keyCompressionTable, combinedKey);
	}

    return subkeys;
}
std::array<uint8_t, 28> TDES::ShiftLeft(std::array<uint8_t, 28> halfKey, int shifts) {
	std::array<uint8_t, 28> shiftedKey{};
	for (std::size_t i = 0; i < 28; i++) {
		shiftedKey[i] = halfKey[(i + shifts) % 28];
	}
	return shiftedKey;
}
template <std::size_t N, std::size_t M>
std::array<std::uint8_t, N> TDES::Permute(const std::array<uint8_t, N>& table,
    const std::array<std::uint8_t, M>& input) {
    std::array<std::uint8_t, N> result{};
    for (std::size_t i = 0; i < N; i++) {
        result[i] = input[table[i]];
    }
    return result;
}

std::array<uint8_t, 64> TDES::DESEncryptBlock(std::array<uint8_t, 64> block, std::array<std::array<uint8_t, 48>, 16> subkeys) {
	std::array<uint8_t, 64> result{};
	std::array<uint8_t, 64> permutedBlock = Permute(initialPermutation, block);

	std::array<uint8_t, 32> left{};
	std::array<uint8_t, 32> right{};
	for (std::size_t i = 0; i < 32; i++) {
		left[i] = permutedBlock[i];
		right[i] = permutedBlock[i + 32];
	}
	// 16 rounds of DES
	for (std::size_t round = 0; round < 16; round++) {
		
		std::array<uint8_t, 32> feistelRound = FeistelFunction(right, subkeys[round]);
		// XOR with left half

		std::transform(left.begin(), left.end(), feistelRound.begin(), left.begin(),
			[](uint8_t l, uint8_t f) { return l ^ f; });

		if (round < 15) {
			std::swap(left, right);

		}

	}
	// Combine halves
	std::array<uint8_t, 64> combinedBlock{};
	for (std::size_t i = 0; i < 32; i++) {
		combinedBlock[i] = left[i];
		combinedBlock[i+32] = right[i];
	}
	// Final permutation
	result = Permute(finalPermutation, combinedBlock);
	return result;
}
std::array<uint8_t, 64> TDES::DESDecryptBlock(std::array<uint8_t, 64> block, std::array<std::array<uint8_t, 48>, 16> subkeys) {
	std::array<uint8_t, 64> result{};
	return result;
}

template <std::size_t N>
std::array<uint8_t, N> TDES::HexStringToBitArray(const std::string& hexStr) {
	std::array<uint8_t, N> bits{};
	for (size_t i = 0; i < hexStr.size(); i++) {
		char hexChar = hexStr[i];
		uint8_t value;
		if (hexChar >= '0' && hexChar <= '9') {
			value = hexChar - '0';
		} else if (hexChar >= 'A' && hexChar <= 'F') {
			value = hexChar - 'A' + 10;
		} else if (hexChar >= 'a' && hexChar <= 'f') {
			value = hexChar - 'a' + 10;
		} else {
			continue; // Skip invalid characters
		}
		// Convert hex digit to 4 bits
		for (int j = 0; j < 4; j++) {
			bits[i * 4 + (3 - j)] = (value >> j) & 1;
		}
	}
	return bits;
}

template <std::size_t N>
std::string TDES::BitArrayToHexString(const std::array<uint8_t, N>& bits) {
	std::string hexStr = "";
	for (size_t i = 0; i < N/4; i++) {
		uint8_t value = 0;
		for (int j = 0; j < 4; j++) {
			value = (value << 1) | bits[i * 4 + j];
		}
		if (value < 10) {
			hexStr += ('0' + value);
		} else {
			hexStr += ('A' + (value - 10));
		}
	}
	return hexStr;
}

template <std::size_t N>
std::array<uint8_t, N> TDES::StringToBitArray(const std::string& str) {
    std::array<uint8_t, N> bits{};
    std::size_t bitCount = std::min(N, str.size() * 8);

    for (std::size_t i = 0; i < bitCount; i++) {
        uint8_t byte = static_cast<uint8_t>(str[i / 8]);
        bits[i] = (byte >> (7 - (i % 8))) & 1;
    }
    return bits;
}

template <std::size_t N>
std::string TDES::BitArrayToString(const std::array<uint8_t, N>& bits) {
	std::string str = "";
	for (int i = 0; i < N; i += 8) {
		char byte = 0;
		for (int j = 0; j < 8; j++) {
			byte = (byte << 1) | bits[i + j];
		}
		str += byte;
	}
	return str;
}
