#include <iostream>
#include "utils/DataConverter.hpp"
#include "cipher/TDES/tdes.hpp"
#include "cipher/AES/aes.hpp"
#include "mode/mode.hpp"
#include "mode/ECB.hpp"
#include "mode/CBC.hpp"
#include "mode/CTR.hpp"


int main() {

	std::string text = "0123456789ABCDEF0123456789ABCDEF";
	std::vector<uint8_t> plaintext = DataConverter::HexToBytes(text);
	std::vector<uint8_t> keyBytes = DataConverter::HexToBytes("033457799BBCDFF1133457799BBCDFF1233457799BBCDFF1");
	std::vector<uint8_t> IV ;
	std::string expectedEncrypted = "37d174403fc04f1a";

	TDES tdes(keyBytes);

	ECB ecb;
	auto test = ecb.encrypt(plaintext, tdes);
	std::cout << "Encrypted: ";
	for (auto b : test) {
		std::cout << std::hex << (int)b;
	}

	std::cout << std::endl;
	std::cout << "Expected : " << expectedEncrypted << std::endl;


	text = "fffffffffffffffffffffffffffffffc";
	plaintext = DataConverter::HexToBytes(text);
	keyBytes = DataConverter::HexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
	expectedEncrypted = "0f59cb5a4b522e2ac56c1a64f558ad9a";
	IV = DataConverter::HexToBytes("00000000000000000000000000000000");

	CBC cbc;
	AES aes(keyBytes);
	cbc.setPadding(PaddingMode::None);
	cbc.setIV(IV);

	test = cbc.encrypt(plaintext, aes);
	std::cout << "Encrypted: ";
	for (auto b : test) {
		std::cout << std::hex << (int)b;
	}

	std::cout << std::endl;
	std::cout << "Expected : " << expectedEncrypted << std::endl;





	return 0;
}
